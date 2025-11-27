# staker_rewards.py (module form)
import os, json, time
from datetime import datetime, timezone
from typing import Dict, List
from web3 import Web3
from decimal import Decimal, getcontext
getcontext().prec = 50

ERC20_ABI = [
    {"type":"function","stateMutability":"view","name":"symbol","inputs":[],"outputs":[{"type":"string"}]},
]

def pretty_decimal(d: Decimal, max_dp: int = 18) -> str:
    # Format like '0.00646908' (no scientific notation), trim trailing zeros
    s = format(d, 'f')  # force fixed notation
    if '.' in s:
        # clamp to max_dp decimals
        integer, frac = s.split('.', 1)
        frac = frac[:max_dp]
        s = integer + ('.' + frac if frac else '')
        s = s.rstrip('0').rstrip('.')
    return s

class SymbolResolver:
    def __init__(self, w3: Web3, active_symbol_map: dict[str, str] | None = None):
        self.w3 = w3
        self.cache: dict[str, str] = {}
        if active_symbol_map:
            self.cache.update({k.lower(): v for k, v in active_symbol_map.items() if v})

    def get(self, addr_lc: str) -> str:
        if addr_lc in self.cache:
            return self.cache[addr_lc]
        try:
            c = self.w3.eth.contract(address=self.w3.to_checksum_address(addr_lc), abi=ERC20_ABI)
            sym = c.functions.symbol().call()
            if not isinstance(sym, str):
                sym = str(sym)
        except Exception:
            sym = addr_lc[:6] + '…' + addr_lc[-4:]
        self.cache[addr_lc] = sym
        return sym


# (… keep the same POA shim, DIST_ABI, helpers: load_json, save_json, to_lower_set, checksum_list, human_amount …)

def build_staker_rewards(
    rpc: str,
    chain_id: int,
    epochs_path: str,
    stakers_path: str,
    active_path: str,
    use_prices: bool = False,
    aerodrome_factory: str | None = None,
    usdc_addr: str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
    weth_addr: str = "0x4200000000000000000000000000000000000006",
    max_price_usd: float = 50000.0,
):
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    try:
        from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware as _POA
        w3.middleware_onion.inject(_POA, layer=0)
    except Exception:
        pass

    def _load(p): 
        with open(p,"r") as f: return json.load(f)

    epochs = _load(epochs_path)
    stakers = _load(stakers_path)
    active = _load(active_path)

    active_symbol_map: dict[str, str] = {}
    for t in (active.get("tokens") or []):
        if isinstance(t, dict):
            addr = (t.get("address") or "").lower()
            sym = t.get("symbol")
            if addr and sym:
                active_symbol_map[addr] = sym

    symbol_resolver = SymbolResolver(w3, active_symbol_map=active_symbol_map)

    # Prefer a single canonical distributor field; keep backward compat
    dist_addr = (
        epochs.get("distributorAddress")
        or active.get("distributorAddress")
        or active.get("distributor")
    )
    if not dist_addr:
        raise RuntimeError("No distributorAddress/distributor found in epochs.json/active_reward_tokens.json")

    dist = w3.eth.contract(address=w3.to_checksum_address(dist_addr), abi=[
        {"type":"function","stateMutability":"view","name":"previewClaimsForEpoch",
         "inputs":[{"name":"user","type":"address"},{"name":"tokens","type":"address[]"},{"name":"epochId","type":"uint256"}],
         "outputs":[{"type":"uint256[]"}]}
    ])

    # ---------------- Token universe: registry + distributor balances ----------------
    # active_reward_tokens.json should contain tokens discovered from registry->balance scan.
    # Accept either [{address,decimals,symbol}, ...] or ["0x...", ...].
    def _tok_addr(x):
        return (x.get("address") if isinstance(x, dict) else x or "").lower()

    all_funded = sorted(int(e) for e in (epochs.get("epochs") or {}).keys())    
    # Build per-epoch token lists from epochs.json
    def lower_list(x):
        seen = set()
        for a in x or []:
            lo = (a.get("address") if isinstance(a, dict) else a or "").lower()
            if lo:
                seen.add(lo)
        return sorted(seen)

    per_epoch_tokens_lc = {
        eid: lower_list((epochs["epochs"].get(str(eid)) or {}).get("tokens"))
        for eid in all_funded
    }

    # union of all tokens for pricing/decimals
    tok_universe = sorted({t for toks in per_epoch_tokens_lc.values() for t in toks})


    # ---------------- Epoch scope (default: current + previous) ----------------

    current_epoch = None
    if "currentEpoch" in epochs and isinstance(epochs["currentEpoch"], (int, str)):
        current_epoch = int(epochs["currentEpoch"])
    elif all_funded:
        current_epoch = all_funded[-1]
    epoch_set = all_funded[:]  # already "all funded"


    # Optional prices
    price_map: Dict[str,float] = {}
    fetched = {}
    if use_prices:
        try:
            from price_fetcher import PriceFetcher
            pf = PriceFetcher(
                chain_slug="base",
                cache_file="price_cache.json",
                ttl_sec=300,
                rpc_url=rpc,
                aerodrome_factory=aerodrome_factory,
                usdc=usdc_addr,
                weth=weth_addr,
                max_price_usd=max_price_usd,
            )
            fetched = pf.fetch_batch(tok_universe)
        except Exception:
            pass

    price_map = {k.lower(): float(v.get("priceUsd", 0.0)) for k, v in (fetched or {}).items()}


    holders = [h["address"] for h in (stakers.get("holders") or [])]

    # Decimals map (fallback 18)
    dec_map = {t: 18 for t in tok_universe}
    for t in (active.get("tokens") or []):
        lo = (t.get("address") if isinstance(t, dict) else t or "").lower()
        if lo in dec_map:
            dec_map[lo] = int(t.get("decimals", 18)) if isinstance(t, dict) else 18

 

    rows = []
    totals_by_token_usd: Dict[str,float] = {}

    def checksum_list(addrs_lc: List[str]) -> List[str]:
        out=[]
        for a in addrs_lc:
            try: out.append(w3.to_checksum_address(a))
            except: pass
        return out

    for user in holders:
        user_cs = w3.to_checksum_address(user)
        items = []
        total_usd = 0.0

        for eid in epoch_set:
            toks_lc = per_epoch_tokens_lc.get(eid, [])
            if not toks_lc:
                continue
            toks_cs = checksum_list(toks_lc)
            try:
                amounts = dist.functions.previewClaimsForEpoch(user_cs, toks_cs, eid).call()
            except Exception:
                amounts = [0] * len(toks_cs)

            for lo, raw in zip(toks_lc, amounts):
                raw_i = int(raw)
                if raw_i == 0:
                    continue
                dec = int(dec_map.get(lo, 18))
                human_dec = Decimal(raw_i) / (Decimal(10) ** dec)
                human_str = pretty_decimal(human_dec)
                human_float = float(human_dec)
                px = float(price_map.get(lo, 0.0))
                usd = human_float * px
                sym = symbol_resolver.get(lo)
                items.append({
                    "token": lo,
                    "symbol": sym,
                    "decimals": dec,
                    "amount": str(raw_i),
                    "amountHuman": human_float,
                    "amountHumanStr": human_str,
                    "priceUsd": px,
                    "usd": usd,
                    "epoch": eid,
                })
                totals_by_token_usd[lo] = totals_by_token_usd.get(lo, 0.0) + usd
                total_usd += usd

        # (optional) sort items — newest epoch first, then by USD desc
        items.sort(key=lambda r: (r["epoch"], r["usd"], r["symbol"]), reverse=True)


        rows.append({
            "address": user,
            "pending": items,
            "pendingTokenCount": len(items),
            "totalUsd": total_usd
        })

    # ========== Build enhanced summary ==========
    
    MIN_USD_FOR_SUMMARY = 50.0
    
    # Build summary for each wallet with > $50 owed
    # Sorted by totalUsd descending
    qualified_wallets = [r for r in rows if r["totalUsd"] > MIN_USD_FOR_SUMMARY]
    qualified_wallets.sort(key=lambda r: r["totalUsd"], reverse=True)
    
    wallet_summaries = []
    for wallet in qualified_wallets:
        # Aggregate USD by token for this wallet's pending items
        wallet_token_usd: Dict[str, float] = {}
        for item in wallet["pending"]:
            token = item["token"]
            wallet_token_usd[token] = wallet_token_usd.get(token, 0.0) + item["usd"]
        
        # Get top 5 tokens for this wallet, sorted descending by USD
        sorted_tokens = sorted(
            wallet_token_usd.items(),
            key=lambda kv: kv[1],
            reverse=True
        )[:5]
        
        top_5 = [
            {
                "token": addr,
                "symbol": symbol_resolver.get(addr),
                "usd": usd_val
            }
            for addr, usd_val in sorted_tokens
        ]
        
        wallet_summaries.append({
            "address": wallet["address"],
            "totalUsdOwed": wallet["totalUsd"],
            "top5Tokens": top_5
        })

    out = {
        # ===== NEW: Per-wallet summaries (>$50 owed) =====
        "walletSummaries": wallet_summaries,
        # ===== Existing fields =====
        "asOf": int(time.time()),
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "updateTimestamp": int(datetime.now(timezone.utc).timestamp()),
        "chainId": chain_id,
        "distributor": w3.to_checksum_address(dist_addr),
        "holderCount": len(rows),
        "activeTokensNow": tok_universe,   # was active_now; use union or drop this field
        "fundedEpochs": all_funded,
        "currentEpoch": int(epochs.get("currentEpoch")) if epochs.get("currentEpoch") is not None else (all_funded[-1] if all_funded else None),
        "defaultEpochs": epoch_set,
        "holders": rows,
        "summary": {
            "totalUsd": sum(r["totalUsd"] for r in rows),
            "totalByTokenUsd": totals_by_token_usd
        }
    }
    return out