# price_fetcher.py
import os
import time
import json
import math
import logging
import requests
from typing import Dict, List, Optional, Tuple

from web3 import Web3

logger = logging.getLogger(__name__)

LLAMA_URL = "https://coins.llama.fi/prices/current/{}"  # {chain:addr,...}
CG_SIMPLE_URL = (
    "https://pro-api.coingecko.com/api/v3/simple/token_price/{}"
)  # {platform: base|ethereum}?contract_addresses=&vs_currencies=usd
AERODROME_FACTORY="0x420DD381b31aEf6683db6B902084cB0FFECe40Da"
# Aero (post-migration, 2026-10-22) v2 pool factories: one factory per pool type.
AERO_VOLATILE_FACTORY="0x8E6a9FCd1d638CC760Ffba397605Fe3355dE76D2"
AERO_STABLE_FACTORY="0x78589E876edcEbdce72ee3436ab3c9AD3a7cEF2D"
WETH_ADDRESS="0x4200000000000000000000000000000000000006"
USDC_ADDRESS="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
ZERO_ADDRESS="0x0000000000000000000000000000000000000000"
MAX_PRICE_USD = 10_000_000.0     # sanity cap on any price (BTC wrappers trade above $50k)
DEX_MIN_QUOTE_USD = 25_000.0     # a pool needs this much USDC (or WETH, in USD) on its quote side to price a token
DEX_QUOTE_NOTIONAL_USD = 10.0    # size of the test swap the DEX price is scaled from
# Core tokens (Base): an aggregator price older than LLAMA_MAX_AGE_SEC is treated as missing (DefiLlama kept iAERO's
# last price for hours after the Aerodrome pools were drained on 22 Oct 2026)
AERO_ADDRESS = "0x3f5bf3edac59d650d8fdf9657a71f2f904a3a4ee"      # Aero AERO
IAERO_ADDRESS = "0x81034fb34009115f215f5d5f564aac9ffa46a1dc"
CORE_TOKENS = (AERO_ADDRESS, IAERO_ADDRESS)
LLAMA_MAX_AGE_SEC = 2 * 3600
# iAERO route: iAERO = AERO price x AERO per iAERO from the Aero AERO/iAERO CL100 pool's slot0 (token0 AERO, token1
# iAERO; checked on chain), cross-checked against the Aero v2 AERO/iAERO pool (refused if > 3% apart). iAERO has no
# USDC/WETH pool, so the generic DEX fallback never prices it.
IAERO_CL_POOL = "0x361D728c97E591Ef47A68CAe2DC5C8ef475608EB"
IAERO_V2_POOL = "0x72Decb30DFE4F6Cf7Db3ba1D58411dDda5ed903b"
IAERO_ROUTE_MAX_DIFF = 0.03


# --- Aerodrome / Velodrome-style ABIs ---
# Aerodrome PoolFactory: getPool(a,b,stable). It has no getPair (calls revert).
FACTORY_ABI = [
    {"inputs":[
        {"internalType":"address","name":"tokenA","type":"address"},
        {"internalType":"address","name":"tokenB","type":"address"},
        {"internalType":"bool","name":"stable","type":"bool"}],
     "name":"getPool","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"}
]

# Aero v2 factories: getPool(a,b) with NO stable flag (the factory decides the pool type).
AERO_FACTORY_ABI = [
    {"inputs":[
        {"internalType":"address","name":"tokenA","type":"address"},
        {"internalType":"address","name":"tokenB","type":"address"}],
     "name":"getPool","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"}
]

PAIR_ABI = [
    {"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"getReserves","outputs":[
        {"internalType":"uint256","name":"reserve0","type":"uint256"},
        {"internalType":"uint256","name":"reserve1","type":"uint256"},
        {"internalType":"uint256","name":"blockTimestampLast","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[
        {"internalType":"uint256","name":"amountIn","type":"uint256"},
        {"internalType":"address","name":"tokenIn","type":"address"}],
     "name":"getAmountOut","outputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"}],
     "stateMutability":"view","type":"function"}
]

# Aero CL (Slipstream) pool: token0/token1 and slot0 (sqrtPriceX96 first)
CL_POOL_ABI = [
    {"inputs":[],"name":"token0","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"token1","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"slot0","outputs":[
        {"internalType":"uint160","name":"sqrtPriceX96","type":"uint160"},
        {"internalType":"int24","name":"tick","type":"int24"},
        {"internalType":"uint16","name":"observationIndex","type":"uint16"},
        {"internalType":"uint16","name":"observationCardinality","type":"uint16"},
        {"internalType":"uint16","name":"observationCardinalityNext","type":"uint16"},
        {"internalType":"bool","name":"unlocked","type":"bool"}],
     "stateMutability":"view","type":"function"},
]

ERC20_DEC_ABI = [
    {"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],
     "stateMutability":"view","type":"function"}
]

def _now() -> int:
    return int(time.time())

class PriceFetcher:
    """
    Price cache with:
      1) DefiLlama (primary)
      2) CoinGecko (fallback)
      3) On-chain quoter (final fallback): the deepest token/USDC or token/WETH pool across Aero and legacy
         Aerodrome (by quote-side reserve, at least DEX_MIN_QUOTE_USD), quoted with a ~$10 swap and scaled
    Unpriced tokens come back as 0.0 (source "none") and are never cached.
    Cache key: "{chain}:{addrLower}"
    """

    def __init__(
        self,
        chain_slug: str = "base",
        cache_file: str = "price_cache.json",
        ttl_sec: int = 300,
        # DEX quoter:
        rpc_url: Optional[str] = None,
        aerodrome_factory: Optional[str] = None,
        usdc: Optional[str] = None,
        weth: Optional[str] = None,
        max_price_usd: float = MAX_PRICE_USD,
        aero_volatile_factory: Optional[str] = None,
        aero_stable_factory: Optional[str] = None,
        dex_min_quote_usd: float = DEX_MIN_QUOTE_USD,
    ):
        self.chain = chain_slug
        self.cache_file = cache_file
        self.ttl = ttl_sec
        self.mem: Dict[str, dict] = {}
        self.cg_key = os.environ.get("COINGECKO_API_KEY")  # optional
        self.max_price_usd = max_price_usd
        self.dex_min_quote_usd = dex_min_quote_usd
        self._weth_usd_px: Optional[float] = None   # DEX WETH price, computed once per _fetch_dex
        self.core_tokens = set(CORE_TOKENS) if chain_slug == "base" else set()

        # web3 for quoter
        self.w3: Optional[Web3] = None
        self.factory = None          # Aerodrome (legacy) PoolFactory
        self.aero_factories = []     # Aero v2 factories, in lookup order: volatile, stable
        self.usdc = None
        self.weth = None

        if rpc_url and usdc and weth:
            self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 20}))
            aero_volatile_factory = aero_volatile_factory or os.environ.get("AERO_VOLATILE_FACTORY") or AERO_VOLATILE_FACTORY
            aero_stable_factory = aero_stable_factory or os.environ.get("AERO_STABLE_FACTORY") or AERO_STABLE_FACTORY
            self.aero_factories = [
                self.w3.eth.contract(self.w3.to_checksum_address(f), abi=AERO_FACTORY_ABI)
                for f in (aero_volatile_factory, aero_stable_factory)
            ]
            aerodrome_factory = aerodrome_factory or AERODROME_FACTORY
            self.factory = self.w3.eth.contract(self.w3.to_checksum_address(aerodrome_factory), abi=FACTORY_ABI)
            self.usdc = self.w3.to_checksum_address(usdc)
            self.weth = self.w3.to_checksum_address(weth)

        self._load()

    def _key(self, addr: str) -> str:
        return f"{self.chain}:{addr.lower()}"

    def _load(self):
        try:
            with open(self.cache_file, "r") as f:
                obj = json.load(f)
                now = _now()
                for k, v in obj.items():
                    if (isinstance(v, dict) and float(v.get("priceUsd") or 0) > 0
                            and (now - int(v.get("updatedAt", 0)) <= self.ttl * 6)):
                        self.mem[k] = v
        except Exception:
            pass

    def _save(self):
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self.mem, f, indent=2)
        except Exception:
            pass

    def _from_cache(self, addrs: List[str]) -> Tuple[Dict[str, dict], List[str]]:
        now = _now()
        out: Dict[str, dict] = {}
        want: List[str] = []
        for a in addrs:
            k = self._key(a)
            v = self.mem.get(k)
            if v and float(v.get("priceUsd") or 0) > 0 and (now - int(v.get("updatedAt", 0))) <= self.ttl:
                out[a.lower()] = v
            else:
                want.append(a.lower())
        return out, want

    # ---------- Aggregators ----------
    def _fetch_llama(self, addrs: List[str]) -> Dict[str, dict]:
        if not addrs:
            return {}
        uniq = sorted(set(self._key(a) for a in addrs))
        url = LLAMA_URL.format(",".join(uniq))
        now = _now()
        out: Dict[str, dict] = {}
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                coins = r.json().get("coins", {})
                for k, v in coins.items():
                    price = v.get("price")
                    if price is None:
                        continue
                    p = float(price)
                    if not math.isfinite(p) or p <= 0 or p > self.max_price_usd:
                        continue
                    addr = k.split(":")[1]
                    ts = v.get("timestamp")
                    if addr in self.core_tokens and isinstance(ts, (int, float)) and now - int(ts) > LLAMA_MAX_AGE_SEC:
                        logger.warning(f"[PriceFetcher] DefiLlama price of core token {addr} is {(now - int(ts)) / 3600:.1f} h "
                                       f"old (> {LLAMA_MAX_AGE_SEC / 3600:g} h); treated as unpriced")
                        continue
                    entry = {"priceUsd": p, "updatedAt": now, "source": "llama"}
                    self.mem[k] = entry
                    out[addr] = entry
            else:
                logger.warning(f"Llama HTTP {r.status_code}: {r.text[:160]}")
        except Exception as e:
            logger.warning(f"Llama fetch error: {e}")
        return out

    def _fetch_coingecko(self, addrs: List[str]) -> Dict[str, dict]:
        if not addrs:
            return {}
        now = _now()
        out: Dict[str, dict] = {}
        headers = {}
        if self.cg_key:
            headers["x-cg-pro-api-key"] = self.cg_key
        CHUNK = 100
        for i in range(0, len(addrs), CHUNK):
            chunk = addrs[i:i+CHUNK]
            params = {"contract_addresses": ",".join(chunk), "vs_currencies": "usd", "include_last_updated_at": "true"}
            try:
                r = requests.get(CG_SIMPLE_URL.format(self.chain), params=params, headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json()  # { "0xaddr": {"usd": price}, ... }
                    for k, v in data.items():
                        usd = v.get("usd")
                        if usd is None:
                            continue
                        p = float(usd)
                        if not math.isfinite(p) or p <= 0 or p > self.max_price_usd:
                            continue
                        k_lower = k.lower()
                        ts = v.get("last_updated_at")
                        if k_lower in self.core_tokens and (not isinstance(ts, (int, float))
                                                            or now - int(ts) > LLAMA_MAX_AGE_SEC):
                            logger.warning(f"[PriceFetcher] CoinGecko price of core token {k_lower} is stale or "
                                           f"undated; treated as unpriced")
                            continue
                        entry = {"priceUsd": p, "updatedAt": now, "source": "coingecko"}
                        self.mem[self._key(k_lower)] = entry
                        out[k_lower] = entry
                else:
                    logger.warning(f"CG HTTP {r.status_code}: {r.text[:160]}")
            except Exception as e:
                logger.warning(f"CG fetch error: {e}")
        return out

    # ---------- Aero / Aerodrome quoter (final fallback) ----------
    def _decimals(self, addr: str) -> int:
        try:
            c = self.w3.eth.contract(self.w3.to_checksum_address(addr), abi=ERC20_DEC_ABI)
            d = c.functions.decimals().call()
            return int(d) if d else 18
        except Exception:
            return 18

    def _pair(self, a: str, b: str, stable: bool) -> Optional[str]:
        try:
            p = self.factory.functions.getPool(
                self.w3.to_checksum_address(a), self.w3.to_checksum_address(b), stable
            ).call()
            if p and p != ZERO_ADDRESS:
                return self.w3.to_checksum_address(p)
        except Exception:
            pass
        return None

    def _aero_pool(self, factory, a: str, b: str) -> Optional[str]:
        try:
            p = factory.functions.getPool(
                self.w3.to_checksum_address(a), self.w3.to_checksum_address(b)
            ).call()
            if p and p != ZERO_ADDRESS:
                return self.w3.to_checksum_address(p)
        except Exception:
            pass
        return None

    def _pools(self, a: str, b: str, aero: bool) -> List[str]:
        if aero:
            pools = [self._aero_pool(f, a, b) for f in self.aero_factories]  # volatile, then stable
        elif self.factory:
            pools = [self._pair(a, b, stable) for stable in (False, True)]
        else:
            pools = []
        return [p for p in pools if p]

    def _deepest_pool(self, token: str, quote: str) -> Optional[Tuple[str, int, int]]:
        """(pool, token reserve, quote reserve) of the token/quote pool with the largest quote-side reserve,
        across Aero (volatile, stable) and legacy Aerodrome (volatile, stable)."""
        best = None
        for aero in (True, False):
            for pool in self._pools(token, quote, aero):
                try:
                    c = self.w3.eth.contract(pool, abi=PAIR_ABI)
                    t0 = c.functions.token0().call()
                    r0, r1 = c.functions.getReserves().call()[:2]
                except Exception:
                    continue
                r_tok, r_quote = (int(r0), int(r1)) if t0.lower() == token.lower() else (int(r1), int(r0))
                if r_tok > 0 and r_quote > 0 and (best is None or r_quote > best[2]):
                    best = (pool, r_tok, r_quote)
        return best

    def _quote_usd(self, pool: str, token: str, r_tok: int, r_quote: int, tok_dec: int, quote_dec: int,
                   quote_usd: float) -> Optional[float]:
        """USD price of `token` from a ~DEX_QUOTE_NOTIONAL_USD swap into `pool`, scaled to one token."""
        spot = (r_quote / 10 ** quote_dec) / (r_tok / 10 ** tok_dec) * quote_usd   # sizes the swap only
        amt_in = max(1, int(DEX_QUOTE_NOTIONAL_USD / spot * 10 ** tok_dec)) if spot > 0 else 10 ** tok_dec
        try:
            out = self.w3.eth.contract(pool, abi=PAIR_ABI).functions.getAmountOut(
                amt_in, self.w3.to_checksum_address(token)).call()
        except Exception:
            return None
        if not out or out <= 0:
            return None
        return (out / 10 ** quote_dec) * quote_usd / (amt_in / 10 ** tok_dec)

    def _weth_usd(self) -> Optional[float]:
        if self._weth_usd_px is None:
            self._weth_usd_px = self._dex_price_one(self.weth) or 0.0
        return self._weth_usd_px or None

    def _dex_price_one(self, addr: str) -> Optional[float]:
        """USD price of one token from the DEX fallback (see _dex_quote), or None if not quotable."""
        q = self._dex_quote(addr)
        return q[0] if q else None

    def _dex_quote(self, addr: str) -> Optional[Tuple[float, float, str]]:
        """
        (USD price, quote-side USD depth, pool) of one token from the deepest token/USDC or token/WETH pool on Aero
        or legacy Aerodrome, measured by quote-side reserve in USD (WETH valued at its own deepest WETH/USDC pool).
        The pool must hold at least dex_min_quote_usd on its quote side; the price comes from a ~$10 swap.
        Returns None if not quotable.
        """
        if not (self.w3 and self.usdc and self.weth):
            return None
        token = self.w3.to_checksum_address(addr)
        tok_dec = self._decimals(token)

        routes = []   # (quote-side USD depth, pool, token reserve, quote reserve, quote decimals, quote USD price)
        best = self._deepest_pool(token, self.usdc)
        if best:
            routes.append((best[2] / 10 ** 6, *best, 6, 1.0))           # USDC has 6 decimals on Base
        if token != self.weth:
            best = self._deepest_pool(token, self.weth)
            weth_px = self._weth_usd() if best else None
            if best and weth_px:
                routes.append((best[2] / 10 ** 18 * weth_px, *best, 18, weth_px))
        if not routes:
            return None
        depth, pool, r_tok, r_quote, quote_dec, quote_usd = max(routes, key=lambda r: r[0])
        if depth < self.dex_min_quote_usd:
            logger.info(f"[PriceFetcher] DEX: deepest pool for {token} ({pool}) holds ${depth:,.0f} on its quote side "
                        f"(< ${self.dex_min_quote_usd:,.0f}); not priced")
            return None
        price = self._quote_usd(pool, token, r_tok, r_quote, tok_dec, quote_dec, quote_usd)
        return (price, depth, pool) if price and price > 0 and math.isfinite(price) else None

    def _aero_trusted(self, entry: Optional[dict]) -> bool:
        """An AERO price the iAERO route may build on: an aggregator's (recent: stale core prices are dropped), or a
        DEX price from a trusted pool (realized_yield's trusted-DEX rule)."""
        if not entry or float(entry.get("priceUsd") or 0) <= 0:
            return False
        if entry.get("source") in ("llama", "coingecko"):
            return True
        if entry.get("source") == "dex":
            from realized_yield import trusted_dex_tokens, DEX_TRUSTED_DEPTH_USD
            depth_min = float(os.environ.get("DEX_TRUSTED_DEPTH_USD") or DEX_TRUSTED_DEPTH_USD)
            depth = entry.get("dexDepthUsd")
            return AERO_ADDRESS in trusted_dex_tokens() and isinstance(depth, (int, float)) and depth >= depth_min
        return False

    def _aero_per_iaero(self) -> Optional[Tuple[float, float]]:
        """(AERO per iAERO from the CL pool's slot0, from a 1-iAERO v2 swap), or None if a pool can't be read or
        holds other tokens."""
        cs = self.w3.to_checksum_address
        cl = self.w3.eth.contract(cs(IAERO_CL_POOL), abi=CL_POOL_ABI)
        t0, t1 = cl.functions.token0().call().lower(), cl.functions.token1().call().lower()
        if {t0, t1} != {AERO_ADDRESS, IAERO_ADDRESS}:
            logger.warning(f"[PriceFetcher] iAERO route: CL pool {IAERO_CL_POOL} holds {t0}/{t1}; not used")
            return None
        sqrt_p = int(cl.functions.slot0().call()[0])
        if sqrt_p <= 0:
            return None
        d_aero, d_iaero = self._decimals(AERO_ADDRESS), self._decimals(IAERO_ADDRESS)
        # token1 per token0 (whole tokens) = (sqrtPriceX96 / 2^96)^2 * 10^(dec0 - dec1)
        p1_per_0 = (sqrt_p / 2 ** 96) ** 2 * 10 ** ((d_aero - d_iaero) if t0 == AERO_ADDRESS else (d_iaero - d_aero))
        cl_rate = 1.0 / p1_per_0 if t0 == AERO_ADDRESS else p1_per_0
        v2 = self.w3.eth.contract(cs(IAERO_V2_POOL), abi=PAIR_ABI)
        v0 = v2.functions.token0().call().lower()
        v1 = v2.functions.token1().call().lower()
        if {v0, v1} != {AERO_ADDRESS, IAERO_ADDRESS}:
            logger.warning(f"[PriceFetcher] iAERO route: v2 pool {IAERO_V2_POOL} holds {v0}/{v1}; not used")
            return None
        out = int(v2.functions.getAmountOut(10 ** d_iaero, cs(IAERO_ADDRESS)).call())
        return cl_rate, out / 10 ** d_aero

    def _iaero_route(self, aero_entry: Optional[dict]) -> Optional[dict]:
        """iAERO price entry from the route (see IAERO_CL_POOL), or None (iAERO then stays unpriced)."""
        if not self.w3:
            return None
        if not self._aero_trusted(aero_entry):
            logger.warning(f"[PriceFetcher] iAERO route: the AERO price ({aero_entry}) is not trusted; iAERO unpriced")
            return None
        try:
            rates = self._aero_per_iaero()
        except Exception as e:
            logger.warning(f"[PriceFetcher] iAERO route: pool read failed ({str(e)[:120]}); iAERO unpriced")
            return None
        if not rates:
            return None
        cl_rate, v2_rate = rates
        if not (cl_rate > 0 and v2_rate > 0 and math.isfinite(cl_rate)) or abs(cl_rate - v2_rate) / cl_rate > IAERO_ROUTE_MAX_DIFF:
            logger.warning(f"[PriceFetcher] iAERO route: CL {cl_rate:.6f} and v2 {v2_rate:.6f} AERO per iAERO disagree by "
                           f"more than {IAERO_ROUTE_MAX_DIFF:.0%}; iAERO unpriced")
            return None
        price = float(aero_entry["priceUsd"]) * cl_rate
        if not (0 < price <= self.max_price_usd):
            return None
        entry = {"priceUsd": price, "updatedAt": _now(), "source": "route",
                 "route": {"aeroPriceUsd": float(aero_entry["priceUsd"]), "aeroSource": aero_entry.get("source"),
                           "aeroPerIaero": cl_rate, "aeroPerIaeroV2": v2_rate, "clPool": IAERO_CL_POOL.lower(),
                           "v2Pool": IAERO_V2_POOL.lower()}}
        self.mem[self._key(IAERO_ADDRESS)] = entry
        logger.info(f"[PriceFetcher] iAERO from the route: ${price:.6f} = AERO ${float(aero_entry['priceUsd']):.6f} x "
                    f"{cl_rate:.6f} (v2 {v2_rate:.6f})")
        return entry

    def _fetch_dex(self, addrs: List[str]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        now = _now()
        self._weth_usd_px = None
        for a in addrs:
            try:
                q = self._dex_quote(a)
                p = q[0] if q else None
                if p is None or p <= 0 or p > self.max_price_usd or not math.isfinite(p):
                    continue
                # the pool's quote-side depth lets realized_yield tell deep (trusted) pools from thin ones
                entry = {"priceUsd": float(p), "updatedAt": now, "source": "dex",
                         "dexDepthUsd": round(float(q[1]), 2), "dexPool": q[2]}
                self.mem[self._key(a)] = entry
                out[a] = entry
            except Exception as e:
                logger.debug(f"DEX quote failed for {a}: {e}")
        return out

        # ---------- Public ----------
    def fetch_batch(self, addrs: List[str]) -> Dict[str, dict]:
        """
        Return map addr(lower)-> {priceUsd, updatedAt, source}.
        Guarantees a numeric priceUsd (falls back to 0.0 if unquotable).
        Adds logging for coverage at each pricing source.
        """
        start_time = time.time()
        total = len(addrs)
        logger.info(f"[PriceFetcher] Starting batch for {total} tokens")

        out, want = self._from_cache(addrs)
        logger.info(f"[PriceFetcher] Cache hit: {len(out)} | Need fresh: {len(want)}")

        missing = [a for a in want]

        # 1. DefiLlama
        llama = self._fetch_llama(missing)
        logger.info(f"[PriceFetcher] Llama filled {len(llama)} / {len(missing)}")
        out.update(llama)
        missing = [a for a in missing if a not in llama]

        # 2. CoinGecko
        if missing:
            cg = self._fetch_coingecko(missing)
            logger.info(f"[PriceFetcher] CoinGecko filled {len(cg)} / {len(missing)}")
            out.update(cg)
            missing = [a for a in missing if a not in cg]

        # 2b. iAERO: AERO price x AERO per iAERO from the Aero AERO/iAERO pools (no USDC/WETH pool exists)
        if self.core_tokens and IAERO_ADDRESS in missing:
            aero = out.get(AERO_ADDRESS) or self.fetch_batch([AERO_ADDRESS]).get(AERO_ADDRESS)
            route = self._iaero_route(aero)
            if route:
                out[IAERO_ADDRESS] = route
                missing = [a for a in missing if a != IAERO_ADDRESS]

        # 3. DEX fallback (never for iAERO: the route above, or unpriced)
        dex_want = [a for a in missing if not (self.core_tokens and a == IAERO_ADDRESS)]
        if dex_want:
            logger.info(f"[PriceFetcher] DEX fallback for {len(dex_want)} tokens")
            dex = self._fetch_dex(dex_want)
            logger.info(f"[PriceFetcher] DEX filled {len(dex)} / {len(dex_want)}")
            out.update(dex)
            missing = [a for a in missing if a not in dex]

        # 4. Still missing → assign 0.0 (never cached: the next call retries every source)
        if missing:
            now = _now()
            for a in missing:
                self.mem.pop(self._key(a), None)
                out[a] = {"priceUsd": 0.0, "updatedAt": now, "source": "none"}
            logger.warning(f"[PriceFetcher] {len(missing)} tokens still unpriced after all sources")

        took = time.time() - start_time
        logger.info(f"[PriceFetcher] Done. Total priced: {len(out)} / {total} in {took:.2f}s")
        self._save()
        return out


def llama_prices(keys: List[str], timeout: int = 10) -> Dict[str, float]:
    """DefiLlama prices for arbitrary keys ("chain:0xaddr" or "coingecko:<id>"); missing or bad ones are left out."""
    if not keys:
        return {}
    try:
        r = requests.get(LLAMA_URL.format(",".join(sorted(set(keys)))), timeout=timeout)
        if r.status_code != 200:
            logger.warning(f"Llama HTTP {r.status_code}: {r.text[:160]}")
            return {}
        out = {}
        for k, v in (r.json().get("coins") or {}).items():
            p = v.get("price")
            if p is not None and math.isfinite(float(p)) and float(p) > 0:
                out[k] = float(p)
        return out
    except Exception as e:
        logger.warning(f"Llama fetch error: {e}")
        return {}


class MappedPriceFetcher:
    """fetch_batch for a chain DefiLlama may not cover: the chain's own prices first (PriceFetcher), then, for tokens
    still unpriced, the explicit mapping {token: DefiLlama key} (e.g. Robinhood WETH -> Ethereum WETH). Nothing is
    guessed: a token neither priced nor mapped comes back 0.0 (source "none")."""

    def __init__(self, base, mapping: Dict[str, str]):
        self.base = base
        self.mapping = {k.lower(): v for k, v in (mapping or {}).items()}

    def fetch_batch(self, addrs: List[str]) -> Dict[str, dict]:
        out = dict(self.base.fetch_batch(addrs))
        missing = {a.lower(): self.mapping[a.lower()] for a in addrs
                   if float((out.get(a.lower()) or {}).get("priceUsd", 0.0) or 0.0) <= 0 and a.lower() in self.mapping}
        got = llama_prices(list(missing.values())) if missing else {}
        for a, key in missing.items():
            if key in got:
                out[a] = {"priceUsd": got[key], "updatedAt": _now(), "source": f"mapped:{key}"}
        return out

