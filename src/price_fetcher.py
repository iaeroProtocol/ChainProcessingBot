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
    "https://pro-api.coingecko.com/api/v3/simple/token_price/base"
)  # ?contract_addresses=&vs_currencies=usd
AERODROME_FACTORY="0x420DD381b31aEf6683db6B902084cB0FFECe40Da"
# Aero (post-migration, 2026-10-22) v2 pool factories: one factory per pool type.
AERO_VOLATILE_FACTORY="0x8E6a9FCd1d638CC760Ffba397605Fe3355dE76D2"
AERO_STABLE_FACTORY="0x78589E876edcEbdce72ee3436ab3c9AD3a7cEF2D"
WETH_ADDRESS="0x4200000000000000000000000000000000000006"
USDC_ADDRESS="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
ZERO_ADDRESS="0x0000000000000000000000000000000000000000"


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
      3) On-chain quoter (final fallback): Aero pools first, then legacy Aerodrome pools -> never returns null
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
        max_price_usd: float = 50000.0,
        aero_volatile_factory: Optional[str] = None,
        aero_stable_factory: Optional[str] = None,
    ):
        self.chain = chain_slug
        self.cache_file = cache_file
        self.ttl = ttl_sec
        self.mem: Dict[str, dict] = {}
        self.cg_key = os.environ.get("COINGECKO_API_KEY")  # optional
        self.max_price_usd = max_price_usd

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
                    if isinstance(v, dict) and (now - int(v.get("updatedAt", 0)) <= self.ttl * 6):
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
            if v and (now - int(v.get("updatedAt", 0))) <= self.ttl:
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
                    entry = {"priceUsd": p, "updatedAt": now, "source": "llama"}
                    self.mem[k] = entry
                    addr = k.split(":")[1]
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
            params = {"contract_addresses": ",".join(chunk), "vs_currencies": "usd"}
            try:
                r = requests.get(CG_SIMPLE_URL, params=params, headers=headers, timeout=10)
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

    def _quote_direct(self, token_in: str, token_out: str, amount_in: int, aero: bool = False) -> Optional[int]:
        best = 0
        for pair in self._pools(token_in, token_out, aero):
            try:
                pairc = self.w3.eth.contract(pair, abi=PAIR_ABI)
                out = pairc.functions.getAmountOut(amount_in, self.w3.to_checksum_address(token_in)).call()
                if out > best:
                    best = out
            except Exception:
                continue
        return best if best > 0 else None

    def _dex_price_one(self, addr: str) -> Optional[float]:
        """
        Try to compute 1 token -> USDC price via Aero pools, then legacy Aerodrome pools
        (on each DEX: direct, then two-hop via WETH).
        Returns float price or None if not quotable.
        """
        if not (self.w3 and self.usdc and self.weth):
            return None
        token = self.w3.to_checksum_address(addr)
        # 1 token in raw units
        dec = self._decimals(token)
        amt_in = 10 ** dec

        for aero in (True, False):
            # direct: token->USDC
            out = self._quote_direct(token, self.usdc, amt_in, aero)
            if not out:
                # two-hop: token->WETH->USDC
                mid = self._quote_direct(token, self.weth, amt_in, aero)
                out = self._quote_direct(self.weth, self.usdc, mid, aero) if mid else None
            if out:
                # out is USDC raw units; assume USDC has 6 decimals on Base
                price = out / (10 ** 6)
                if price > 0 and math.isfinite(price):
                    return price

        return None

    def _fetch_dex(self, addrs: List[str]) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        now = _now()
        for a in addrs:
            try:
                p = self._dex_price_one(a)
                if p is None or p <= 0 or p > self.max_price_usd or not math.isfinite(p):
                    continue
                entry = {"priceUsd": float(p), "updatedAt": now, "source": "dex"}
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

        # 3. DEX fallback
        if missing:
            logger.info(f"[PriceFetcher] DEX fallback for {len(missing)} tokens")
            dex = self._fetch_dex(missing)
            logger.info(f"[PriceFetcher] DEX filled {len(dex)} / {len(missing)}")
            out.update(dex)
            missing = [a for a in missing if a not in dex]

        # 4. Still missing → assign 0.0
        if missing:
            now = _now()
            for a in missing:
                entry = {"priceUsd": 0.0, "updatedAt": now, "source": "none"}
                self.mem[self._key(a)] = entry
                out[a] = entry
            logger.warning(f"[PriceFetcher] {len(missing)} tokens still unpriced after all sources")

        took = time.time() - start_time
        logger.info(f"[PriceFetcher] Done. Total priced: {len(out)} / {total} in {took:.2f}s")
        self._save()
        return out

