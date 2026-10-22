# position_earnings.py
"""
Real-time earnings of the protocol's Aero stake (veNFT, e.g. #1584): the `live` block of
data/estimated_rewards_usd.json. Read-only.

Per chain (Base + Ethereum; chain 4663 has no RPC and is reported as unmeasured):
  gauges   = LeafVoter.allocatedGauges(tokenId)  (+ gauges in the previous live block, so a re-vote
             doesn't drop earnings still sitting on a gauge the stake left)
  VRM      = FactoryRegistry.gaugeToRewards(gauge) on Base, else gauge.votingRewardsManager()
  earned   = VRM.earnedFees(tokenId, maxCk)              (token0/token1; includes uncredited fees)
           + VRM.earnedIncentives(tokenId, programId, maxCk) for programId 1..incentiveCount()
           + claimed so far (ClaimFees / ClaimIncentives logs for tokenId), so the total is cumulative
  since    = LeafVoter.tokenStates(tokenId).lastAllocated, but never later than the stake's first
             allocation when known (lastAllocated moves on every re-vote while earnings stay on the VRM)
Valuation uses CURRENT prices. usdPerDay = accruedUSD / elapsed days (since allocation).
  positionAprPct        = usdPerDay*365 / (staked AERO * AERO price)            (the position's own yield)
  projectedStakerApyPct = usdPerDay*365 * stakers share / staked iAERO USD      (same denominator as apyPct)
"""
import math
import time
import logging
from typing import Dict, List, Optional

from eth_utils import keccak

logger = logging.getLogger(__name__)

LEAF_VOTER = "0x382409fad8503FbCdbB27A4211551fa03e884078"         # same address on every Aero chain
FACTORY_REGISTRY_BASE = "0x7b2A2c12dC5Ea2a31455952a05031C3E4BB28F3E"
VOTING_ESCROW = "0xBF7977E1521e9a3032bf7243Ee4712f311f13915"      # Base
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"         # same address on Base and Ethereum
DEFAULT_STAKE_ID = 1584
FIRST_ALLOCATION = {1584: 1792635063}                              # #1584 first allocated 2026-10-22 02:11:03 UTC
UNMEASURED_CHAINS = [4663]                                         # no RPC; its allocation earns but isn't measured
BLOCK_TIME = {8453: 2, 1: 12}
MAX_CHECKPOINTS = 10_000
MAX_SANE_PCT = 500.0

CLAIM_FEES_TOPIC = "0x" + keccak(text="ClaimFees(uint256,address,address,uint256)").hex()
CLAIM_INCENTIVES_TOPIC = "0x" + keccak(text="ClaimIncentives(uint256,address,uint256,uint256)").hex()
ZERO = "0x0000000000000000000000000000000000000000"

AGG3_ABI = [{"name": "aggregate3", "type": "function", "stateMutability": "payable",
             "inputs": [{"name": "calls", "type": "tuple[]", "components": [
                 {"name": "target", "type": "address"}, {"name": "allowFailure", "type": "bool"},
                 {"name": "callData", "type": "bytes"}]}],
             "outputs": [{"name": "returnData", "type": "tuple[]", "components": [
                 {"name": "success", "type": "bool"}, {"name": "returnData", "type": "bytes"}]}]}]


class ChainReader:
    """Batched, block-pinned eth_calls through Multicall3 (allowFailure) plus chunked eth_getLogs."""

    def __init__(self, w3, chain_id: int, block: Optional[int] = None, multicall: str = MULTICALL3, chunk: int = 100):
        self.w3, self.chain_id, self.chunk = w3, chain_id, chunk
        self.block = block if block is not None else max(0, int(w3.eth.block_number) - 2)
        self.block_ts = int(w3.eth.get_block(self.block)["timestamp"])
        self.mc = w3.eth.contract(w3.to_checksum_address(multicall), abi=AGG3_ABI)

    def _retry(self, fn, tries: int = 5):
        for i in range(tries):
            try:
                return fn()
            except Exception as e:
                if i == tries - 1 or "429" not in str(e) and "Too Many" not in str(e):
                    raise
                time.sleep(2 ** i)

    def many(self, calls: List[tuple]) -> list:
        """calls: [(target, 'fn(type,...)', [args], [out types])] -> decoded value (single output unwrapped) or None."""
        out: list = [None] * len(calls)
        valid = [(i, c) for i, c in enumerate(calls) if c[0] and c[0] != ZERO]   # no target -> None
        for j in range(0, len(valid), self.chunk):
            idx = [i for i, _ in valid[j:j + self.chunk]]
            part = [c for _, c in valid[j:j + self.chunk]]
            req = []
            for target, sig, args, _ in part:
                in_types = [t for t in sig[sig.index("(") + 1:-1].split(",") if t]
                data = keccak(text=sig)[:4] + (self.w3.codec.encode(in_types, list(args)) if in_types else b"")
                req.append({"target": self.w3.to_checksum_address(target), "allowFailure": True, "callData": data})
            res = self._retry(lambda: self.mc.functions.aggregate3(req).call(block_identifier=self.block))
            for i, (target, sig, args, out_types), (ok, data) in zip(idx, part, res):
                if ok and data:
                    try:
                        dec = self.w3.codec.decode(out_types, bytes(data))
                        out[i] = dec[0] if len(out_types) == 1 else tuple(dec)
                    except Exception:
                        pass
        return out

    def block_at(self, ts: int) -> int:
        bt = BLOCK_TIME.get(self.chain_id, 2)
        return max(0, self.block - max(0, self.block_ts - int(ts)) // bt - 600)  # 600-block margin

    def logs(self, addresses: List[str], topics: list, from_block: int, step: int = 10_000) -> Optional[list]:
        """All logs, or None if the RPC refuses (claims then count as unknown)."""
        out, fb = [], int(from_block)
        addrs = [self.w3.to_checksum_address(a) for a in addresses]
        while fb <= self.block:
            tb = min(self.block, fb + step - 1)
            try:
                out.extend(self._retry(lambda: self.w3.eth.get_logs(
                    {"address": addrs, "fromBlock": fb, "toBlock": tb, "topics": topics}), tries=3))
                fb = tb + 1
            except Exception as e:
                if step > 1_000:
                    step //= 2
                    continue
                logger.warning(f"[position] chain {self.chain_id}: eth_getLogs refused ({str(e)[:120]}); claims unknown")
                return None
        return out


def _topic_int(t) -> int:
    return int(t.hex() if hasattr(t, "hex") else t, 16)


def read_chain_position(reader, token_id: int, leaf_voter: str = LEAF_VOTER, registry: Optional[str] = None,
                        extra_gauges: tuple = (), max_checkpoints: int = MAX_CHECKPOINTS,
                        first_allocation: Optional[int] = None) -> dict:
    """Raw on-chain earnings of `token_id` on one chain (no prices)."""
    gauges, state = reader.many([
        (leaf_voter, "allocatedGauges(uint256)", [token_id], ["address[]"]),
        (leaf_voter, "tokenStates(uint256)", [token_id], ["address", "uint48", "bool", "uint128"]),
    ])
    allocated = [g.lower() for g in (gauges or [])]
    all_gauges = allocated + [g.lower() for g in extra_gauges if g.lower() not in allocated]

    per = []
    for g in all_gauges:
        per += [(leaf_voter, "allocations(uint256,address)", [token_id, g], ["uint128"]),
                (g, "votingRewardsManager()", [], ["address"]),
                (g, "pool()", [], ["address"]),             # CL gauges
                (g, "stakingToken()", [], ["address"])]     # v2 gauges (the pool is the LP token)
        if registry:
            per.append((registry, "gaugeToRewards(address)", [g], ["address"]))
    res = reader.many(per)
    k = 5 if registry else 4
    rows = []
    for i, g in enumerate(all_gauges):
        alloc, vrm_g, pool, lp = res[i * k:i * k + 4]
        vrm_r = res[i * k + 4] if registry else None
        vrm = vrm_r if vrm_r and vrm_r != ZERO else vrm_g
        rows.append({"gauge": g, "vrm": (vrm or "").lower(), "pool": (pool or lp or "").lower(),
                     "allocation": int(alloc or 0), "active": g in allocated})
    rows = [r for r in rows if r["vrm"] and r["vrm"] != ZERO]

    # VRM token order (= earnedFees order); earned fees twice (maxCheckpoints and 2x at the same block:
    # a difference means truncation, and the 2x value is used); program count; pool kind for the label
    per = []
    for r in rows:
        per += [(r["vrm"], "token0()", [], ["address"]),
                (r["vrm"], "token1()", [], ["address"]),
                (r["vrm"], "earnedFees(uint256,uint256)", [token_id, max_checkpoints], ["uint256", "uint256"]),
                (r["vrm"], "earnedFees(uint256,uint256)", [token_id, 2 * max_checkpoints], ["uint256", "uint256"]),
                (r["vrm"], "incentiveCount()", [], ["uint256"]),
                (r["pool"], "tickSpacing()", [], ["int24"])]
    res = reader.many(per)
    progs = []
    for i, r in enumerate(rows):
        t0, t1, f1, f2, n, ts = res[i * 6:i * 6 + 6]
        r["token0"], r["token1"] = (t0 or "").lower(), (t1 or "").lower()
        r["truncated"] = bool(f1 is not None and f2 is not None and tuple(f1) != tuple(f2))
        fees = f2 if r["truncated"] else (f1 or (0, 0))
        r["fees"] = {r["token0"]: int(fees[0]), r["token1"]: int(fees[1])} if r["token0"] and r["token1"] else {}
        r["kind"] = f"CL{ts}" if ts is not None else "v2"
        r["incentives"] = []
        progs += [(r, pid) for pid in range(1, int(n or 0) + 1)]

    per = []
    for r, pid in progs:
        per += [(r["vrm"], "incentive(uint256)", [pid], ["address", "uint256", "uint256", "uint48", "uint48", "address"]),
                (r["vrm"], "earnedIncentives(uint256,uint256,uint256)", [token_id, pid, max_checkpoints], ["uint256"]),
                (r["vrm"], "earnedIncentives(uint256,uint256,uint256)", [token_id, pid, 2 * max_checkpoints], ["uint256"])]
    res = reader.many(per)
    for j, (r, pid) in enumerate(progs):
        inc, e1, e2 = res[j * 3:j * 3 + 3]
        if not inc:
            continue
        trunc = e1 is not None and e2 is not None and e1 != e2
        r["truncated"] = r["truncated"] or trunc
        r["incentives"].append({"programId": pid, "token": inc[0].lower(), "amount": int((e2 if trunc else e1) or 0),
                                "start": int(inc[3]), "end": int(inc[4])})

    # claims so far (cumulative = claimed + unclaimed)
    first = first_allocation if first_allocation is not None else FIRST_ALLOCATION.get(token_id)
    last_alloc = int(state[1]) if state else 0
    since = min(x for x in (last_alloc, first) if x) if (last_alloc or first) else reader.block_ts
    claims = None
    if rows:
        tid_topic = "0x" + int(token_id).to_bytes(32, "big").hex()
        claims = reader.logs([r["vrm"] for r in rows], [[CLAIM_FEES_TOPIC, CLAIM_INCENTIVES_TOPIC], tid_topic],
                             reader.block_at(since))
    by_vrm = {r["vrm"]: r for r in rows}
    for r in rows:
        r["claimed"] = {}
    for lg in claims or []:
        r = by_vrm.get(str(lg["address"]).lower())
        if not r:
            continue
        topic0 = "0x" + (lg["topics"][0].hex() if hasattr(lg["topics"][0], "hex") else lg["topics"][0]).removeprefix("0x")
        amount = _topic_int(lg["data"]) if lg["data"] not in (b"", "0x") else 0
        if topic0 == CLAIM_FEES_TOPIC:
            token = "0x" + format(_topic_int(lg["topics"][3]), "040x")
        else:
            pid = _topic_int(lg["topics"][3])
            token = next((x["token"] for x in r["incentives"] if x["programId"] == pid), None)
            if token is None:
                inc = reader.many([(r["vrm"], "incentive(uint256)", [pid],
                                    ["address", "uint256", "uint256", "uint48", "uint48", "address"])])[0]
                token = inc[0].lower() if inc else None
        if token:
            r["claimed"][token] = r["claimed"].get(token, 0) + amount

    return {"chainId": reader.chain_id, "block": reader.block, "blockTimestamp": reader.block_ts,
            "lastAllocated": last_alloc, "since": int(since), "chainAllocation": int(state[3]) if state else 0,
            "claimsScanned": claims is not None, "gauges": rows}


def token_meta(reader, tokens: List[str]) -> Dict[str, dict]:
    tokens = sorted(set(t for t in tokens if t))
    res = reader.many([(t, "symbol()", [], ["string"]) for t in tokens] +
                      [(t, "decimals()", [], ["uint8"]) for t in tokens])
    n = len(tokens)
    return {t: {"symbol": res[i] if isinstance(res[i], str) else t[:6] + "…" + t[-4:],
                "decimals": int(res[n + i]) if res[n + i] is not None else 18} for i, t in enumerate(tokens)}


def _sane(name: str, v: Optional[float]) -> Optional[float]:
    if v is None or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 or v > MAX_SANE_PCT:
        logger.warning(f"[position] {name}={v} fails the sanity guard (NaN, negative or > {MAX_SANE_PCT}%); omitted")
        return None
    return float(v)


def value_live(chains: List[dict], meta: Dict[int, Dict[str, dict]], prices: Dict[int, Dict[str, float]],
               token_id: int, staked_aero_raw: int, aero_price: float, staked_iaero_usd: float,
               stakers_bps: int = 8000, now_ts: Optional[int] = None, unmeasured: Optional[List[int]] = None) -> dict:
    """Pure: price the raw per-chain reads into the `live` block."""
    now_ts = int(now_ts if now_ts is not None else time.time())
    stake = staked_aero_raw / 1e18 if staked_aero_raw else 0.0
    gauges_out, unpriced = [], set()
    accrued_total = usd_day_total = 0.0
    split_total = {"feesUSD": 0.0, "incentivesUSD": 0.0, "claimedUSD": 0.0}
    measured_alloc = 0

    for ch in chains:
        cid = ch["chainId"]
        elapsed_days = max(0.0, (ch["blockTimestamp"] - ch["since"]) / 86400.0)
        measured_alloc += ch["chainAllocation"]
        for r in ch["gauges"]:
            amounts: Dict[str, int] = {}
            for t, a in list(r["fees"].items()) + [(x["token"], x["amount"]) for x in r["incentives"]] + list(r["claimed"].items()):
                amounts[t] = amounts.get(t, 0) + int(a)
            usd = 0.0
            tokens_out = []
            for t, a in sorted(amounts.items()):
                if a <= 0:
                    continue
                m = meta.get(cid, {}).get(t, {"symbol": t[:6], "decimals": 18})
                px = float(prices.get(cid, {}).get(t, 0.0) or 0.0)
                amt = a / 10 ** m["decimals"]
                if px <= 0:
                    unpriced.add(f"{cid}:{t}")
                tokens_out.append({"token": t, "symbol": m["symbol"], "amount": amt, "usd": amt * px})
                usd += amt * px
            def _usd(pairs):
                tot = 0.0
                for t, a in pairs:
                    m = meta.get(cid, {}).get(t, {"decimals": 18})
                    tot += int(a) / 10 ** m["decimals"] * float(prices.get(cid, {}).get(t, 0.0) or 0.0)
                return tot
            split = {"feesUSD": _usd(r["fees"].items()),
                     "incentivesUSD": _usd((x["token"], x["amount"]) for x in r["incentives"]),
                     "claimedUSD": _usd(r["claimed"].items())}
            for k_, v_ in split.items():
                split_total[k_] += v_
            per_day = usd / elapsed_days if elapsed_days > 0 else 0.0
            accrued_total += usd
            usd_day_total += per_day
            s0 = meta.get(cid, {}).get(r["token0"], {}).get("symbol", "?")
            s1 = meta.get(cid, {}).get(r["token1"], {}).get("symbol", "?")
            gauges_out.append({
                "chainId": cid, "gauge": r["gauge"], "pool": r["pool"],
                "label": f"{s0}/{s1}" + (f" {r['kind']}" if r.get("kind") else ""),
                "votingRewardsManager": r["vrm"], "active": r["active"],
                "allocationAero": r["allocation"] / 1e18,
                "allocationShare": (r["allocation"] / 1e18 / stake) if stake else 0.0,
                "accruedUSD": usd, **split, "usdPerDay": per_day, "truncated": r.get("truncated", False),
                "tokens": tokens_out,
            })

    annual = usd_day_total * 365.0
    stake_usd = stake * float(aero_price or 0.0)
    pos_apr = (annual / stake_usd * 100.0) if stake_usd > 0 else None
    proj = (annual * stakers_bps / 10_000 / staked_iaero_usd * 100.0) if staked_iaero_usd > 0 else None
    since = min((c["since"] for c in chains), default=now_ts)
    out = {
        "method": "live_position",
        "stakeId": int(token_id),
        "asOf": now_ts,
        "since": int(since),
        "elapsedDays": max((c["blockTimestamp"] - c["since"]) / 86400.0 for c in chains) if chains else 0.0,
        "stakedAero": stake,
        "stakedAeroUSD": stake_usd,
        "aeroPriceUsd": float(aero_price or 0.0),
        "stakedIaeroUSD": float(staked_iaero_usd),
        "stakersShareBps": int(stakers_bps),
        "accruedUSD": accrued_total,
        **split_total,
        "usdPerDay": usd_day_total,
        "annualUSD": annual,
        "measuredShareOfAllocation": (measured_alloc / 1e18 / stake) if stake else 0.0,
        "unmeasuredChains": sorted(set(UNMEASURED_CHAINS if unmeasured is None else unmeasured)),
        "chains": [{"chainId": c["chainId"], "block": c["block"], "blockTimestamp": c["blockTimestamp"],
                    "since": c["since"], "lastAllocated": c["lastAllocated"],
                    "allocationAero": c["chainAllocation"] / 1e18, "claimsScanned": c["claimsScanned"]} for c in chains],
        "gauges": gauges_out,
        "unpricedTokens": sorted(unpriced),
        "priceBasis": "current",
        "definitions": {
            "accruedUSD": "fees + incentives earned by the stake since allocation (claimed + unclaimed), current prices; "
                          "feesUSD/incentivesUSD are the unclaimed parts, claimedUSD what was already claimed",
            "usdPerDay": "sum over gauges of accruedUSD / days since allocation on that chain",
            "positionAprPct": "usdPerDay*365 / (staked AERO * AERO price) * 100; unmeasured chains count as earning 0",
            "projectedStakerApyPct": "usdPerDay*365 * stakersShareBps/10000 / stakedIaeroUSD * 100; "
                                     "stakedIaeroUSD is the realized apyPct denominator (staked iAERO at epoch start * iAERO price)",
        },
    }
    for name, v in (("positionAprPct", pos_apr), ("projectedStakerApyPct", proj)):
        v = _sane(name, v)
        if v is not None:
            out[name] = v
    return out


def build_live(chain_readers: List[tuple], token_id: int, price_fetchers: Dict[int, object], staked_aero_raw: int,
               aero_price: float, staked_iaero_usd: float, stakers_bps: int = 8000,
               prev_live: Optional[dict] = None, now_ts: Optional[int] = None,
               first_allocation: Optional[int] = None) -> dict:
    """chain_readers: [(reader, registry_or_None)]. price_fetchers: {chainId: PriceFetcher for that chain}.
    A chain whose reads fail is reported in unmeasuredChains instead of failing the whole block."""
    prev_g = {}
    if prev_live and int(prev_live.get("stakeId", -1)) == int(token_id):
        for g in prev_live.get("gauges") or []:
            prev_g.setdefault(int(g.get("chainId", 0)), []).append(g["gauge"])
    chains, meta, prices, unmeasured = [], {}, {}, list(UNMEASURED_CHAINS)
    for reader, registry in chain_readers:
        try:
            ch = read_chain_position(reader, token_id, registry=registry, first_allocation=first_allocation,
                                     extra_gauges=tuple(prev_g.get(reader.chain_id, [])))
        except Exception as e:
            logger.warning(f"[position] chain {reader.chain_id} read failed ({str(e)[:160]}); reported as unmeasured")
            unmeasured.append(reader.chain_id)
            continue
        chains.append(ch)
        toks = set()
        for r in ch["gauges"]:
            toks |= set(r["fees"]) | {x["token"] for x in r["incentives"]} | set(r["claimed"]) | {r["token0"], r["token1"]}
        toks.discard("")
        meta[reader.chain_id] = token_meta(reader, sorted(toks))
        pf = price_fetchers.get(reader.chain_id)
        got = pf.fetch_batch(sorted(toks)) if (pf and toks) else {}
        prices[reader.chain_id] = {t: float((got.get(t) or {}).get("priceUsd", 0.0)) for t in toks}
    live = value_live(chains, meta, prices, token_id, staked_aero_raw, aero_price, staked_iaero_usd, stakers_bps, now_ts,
                      unmeasured=unmeasured)
    logger.info(
        f"[position] stake #{token_id}: accrued=${live['accruedUSD']:.2f} over {live['elapsedDays']:.3f}d "
        f"-> ${live['usdPerDay']:.2f}/day, positionApr={live.get('positionAprPct')} "
        f"projectedStakerApy={live.get('projectedStakerApyPct')} measured={live['measuredShareOfAllocation']:.3f} "
        f"unpriced={len(live['unpricedTokens'])}"
    )
    return live


def staked_aero(reader, token_id: int, voting_escrow: str = VOTING_ESCROW) -> int:
    """Voting power of the stake (permanent stake: equals the AERO staked)."""
    return int(reader.many([(voting_escrow, "balanceOfNFT(uint256)", [token_id], ["uint256"])])[0] or 0)
