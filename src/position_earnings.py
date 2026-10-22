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
from typing import Callable, Dict, List, Optional

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
        r["claimed"], r["claimedFees"], r["claimedIncentives"] = {}, {}, {}
    for lg in claims or []:
        r = by_vrm.get(str(lg["address"]).lower())
        if not r:
            continue
        topic0 = "0x" + (lg["topics"][0].hex() if hasattr(lg["topics"][0], "hex") else lg["topics"][0]).removeprefix("0x")
        amount = _topic_int(lg["data"]) if lg["data"] not in (b"", "0x") else 0
        is_fee = topic0 == CLAIM_FEES_TOPIC
        if is_fee:
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
            kind = r["claimedFees"] if is_fee else r["claimedIncentives"]
            kind[token] = kind.get(token, 0) + amount

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


# ---------------- trailing windows over live.history ----------------
# A history point stores per-gauge CUMULATIVE token amounts (claimed + unclaimed, fees and incentives apart),
# keyed "chainId:gauge" (gauge addresses can repeat across chains). Deltas are valued at the CURRENT run's prices,
# so price moves on the accumulated stock don't leak into the rate; claims are inside the cumulative, so they never
# show up as negative deltas.
DAY_SEC = 86400
WINDOWS = {"24h": (20 * 3600, 36 * 3600, 24 * 3600),          # (min age, max age, target age) of the snapshot used
           "7d": (6 * DAY_SEC, 8 * DAY_SEC, 7 * DAY_SEC)}
HISTORY_MAX_AGE = int(10.5 * 86400)
HISTORY_MAX_POINTS = 12
HISTORY_MIN_SPACING = 12 * 3600         # one point per ~day; a newer run within 12 h replaces the newest point
DROP_ALERT_RATIO = 0.5                  # 24h rate below 50% of the 7d rate -> alert
ZERO_ALERT_USD_PER_DAY = 1.0            # an allocated gauge under $1/day over 24h counts as earning nothing


def _sig(x: float) -> float:
    return float(f"{x:.8g}")


def pick_snapshot(history: List[dict], now_ts: int, window: str) -> Optional[dict]:
    lo, hi, target = WINDOWS[window]
    cands = [h for h in history or [] if lo <= now_ts - int(h.get("asOf", 0)) <= hi]
    return min(cands, key=lambda h: abs(now_ts - int(h["asOf"]) - target)) if cands else None


def window_delta(cur: dict, snap: dict, price: Callable[[int, str], float]) -> dict:
    """USD earned between `snap` and `cur` (both history points), per gauge and in total, fees apart."""
    days = (int(cur["asOf"]) - int(snap["asOf"])) / 86400.0
    per_gauge, total, fees, negative = {}, 0.0, 0.0, []
    snap_chains = set(snap.get("chains") or {int(k.split(":")[0]) for k in (snap.get("gauges") or {})})
    cur_chains = set(cur.get("chains") or {int(k.split(":")[0]) for k in cur["gauges"]})
    partial = snap_chains != cur_chains          # a chain measured in only one of the two points is left out
    for key, g in cur["gauges"].items():
        old = (snap.get("gauges") or {}).get(key) or {}
        cid = int(key.split(":")[0])
        if cid not in snap_chains:
            continue
        g_usd = g_fee = 0.0
        moved_unpriced = False
        for kind in ("fees", "incentives"):
            for tok, amt in (g.get(kind) or {}).items():
                d = float(amt) - float((old.get(kind) or {}).get(tok, 0.0))
                if d < -1e-9 * max(1.0, abs(float(amt))):
                    negative.append(key)
                    d = 0.0
                px = price(cid, tok)
                if d > 0 and px <= 0:
                    moved_unpriced = True
                usd = d * px
                g_usd += usd
                if kind == "fees":
                    g_fee += usd
        rate = g_usd / days if days > 0 else 0.0
        per_gauge[key] = {"usdPerDay": rate, "earned": rate >= ZERO_ALERT_USD_PER_DAY or moved_unpriced}
        total += g_usd
        fees += g_fee
    return {"days": days, "usdPerDay": total / days if days > 0 else 0.0, "feesUsdPerDay": fees / days if days > 0 else 0.0,
            "gauges": per_gauge, "negative": sorted(set(negative)), "partial": partial}


def _rates(usd_per_day: float, stake_usd: float, staked_iaero_usd: float, stakers_bps: int, label: str) -> dict:
    out = {"usdPerDay": usd_per_day}
    annual = usd_per_day * 365.0
    for name, v in (("positionAprPct", annual / stake_usd * 100.0 if stake_usd > 0 else None),
                    ("projectedStakerApyPct", annual * stakers_bps / 10_000 / staked_iaero_usd * 100.0 if staked_iaero_usd > 0 else None)):
        v = _sane(f"{label}.{name}", v)
        if v is not None:
            out[name] = v
    return out


def value_live(chains: List[dict], meta: Dict[int, Dict[str, dict]], prices: Dict[int, Dict[str, float]],
               token_id: int, staked_aero_raw: int, aero_price: float, staked_iaero_usd: float,
               stakers_bps: int = 8000, now_ts: Optional[int] = None, unmeasured: Optional[List[int]] = None,
               prev_history: Optional[List[dict]] = None) -> dict:
    """Pure: price the raw per-chain reads into the `live` block (plus trailing windows over prev_history)."""
    now_ts = int(now_ts if now_ts is not None else time.time())
    stake = staked_aero_raw / 1e18 if staked_aero_raw else 0.0
    gauges_out, unpriced = [], set()
    accrued_total = usd_day_total = 0.0
    split_total = {"feesUSD": 0.0, "incentivesUSD": 0.0, "claimedUSD": 0.0}
    measured_alloc = 0
    fees_day_total = 0.0
    point = {"asOf": now_ts, "chains": sorted(c["chainId"] for c in chains), "accruedUSD": 0.0, "feesCumUSD": 0.0,
             "gauges": {}}

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
            # cumulative amounts (claimed + unclaimed) per kind, for feesOnly and the history point
            dec = lambda t: meta.get(cid, {}).get(t, {}).get("decimals", 18)
            cum_f: Dict[str, float] = {}
            cum_i: Dict[str, float] = {}
            for t, a in list(r["fees"].items()) + list(r.get("claimedFees", {}).items()):
                cum_f[t] = cum_f.get(t, 0.0) + int(a) / 10 ** dec(t)
            for t, a in [(x["token"], x["amount"]) for x in r["incentives"]] + list(r.get("claimedIncentives", {}).items()):
                cum_i[t] = cum_i.get(t, 0.0) + int(a) / 10 ** dec(t)
            fees_cum_usd = sum(a * float(prices.get(cid, {}).get(t, 0.0) or 0.0) for t, a in cum_f.items())
            fees_day_total += fees_cum_usd / elapsed_days if elapsed_days > 0 else 0.0
            point["gauges"][f"{cid}:{r['gauge']}"] = {
                "usd": _sig(usd),
                "fees": {t: _sig(a) for t, a in cum_f.items() if a > 0},
                "incentives": {t: _sig(a) for t, a in cum_i.items() if a > 0}}
            point["accruedUSD"] += usd
            point["feesCumUSD"] += fees_cum_usd
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

    # ---- trailing 24h / 7d windows from previous published history ----
    point["accruedUSD"], point["feesCumUSD"] = _sig(point["accruedUSD"]), _sig(point["feesCumUSD"])
    history = [h for h in (prev_history or []) if isinstance(h, dict) and int(h.get("asOf", 0)) < now_ts]
    price = lambda cid, t: float(prices.get(cid, {}).get(t, 0.0) or 0.0)
    trailing, fees_trailing, deltas, alerts = {}, {}, {}, []
    claims_ok = all(c["claimsScanned"] for c in chains)
    for w in WINDOWS:
        snap = pick_snapshot(history, now_ts, w)
        if not snap:
            trailing[w] = fees_trailing[w] = None
            continue
        d = window_delta(point, snap, price)
        deltas[w] = d
        meta_w = {"snapshotAsOf": int(snap["asOf"]), "snapshotAgeHours": round((now_ts - int(snap["asOf"])) / 3600.0, 2),
                  "claimsComplete": claims_ok, "partial": d["partial"]}
        trailing[w] = {**meta_w, **_rates(d["usdPerDay"], stake_usd, staked_iaero_usd, stakers_bps, f"trailing.{w}")}
        fees_trailing[w] = {**meta_w, **_rates(d["feesUsdPerDay"], stake_usd, staked_iaero_usd, stakers_bps, f"feesOnly.{w}")}
        for key in d["negative"]:
            alerts.append({"type": "negative_delta", "window": w, "gauge": key,
                           "message": f"cumulative earnings fell on {key} over {w} (claims not scanned?); delta set to 0"})
    for g in gauges_out:
        key = f"{g['chainId']}:{g['gauge']}"
        for w in WINDOWS:
            g[f"usdPerDay{w}"] = deltas[w]["gauges"].get(key, {}).get("usdPerDay") if w in deltas else None
        d24 = deltas.get("24h")
        if d24 and g["active"] and key in d24["gauges"] and not d24["gauges"][key]["earned"]:
            alerts.append({"type": "gauge_no_earnings_24h", "chainId": g["chainId"], "gauge": g["gauge"], "label": g["label"],
                           "usdPerDay24h": d24["gauges"][key]["usdPerDay"],
                           "message": f"allocated gauge {g['label']} ({key}) earned ${d24['gauges'][key]['usdPerDay']:.2f}/day "
                                      f"(< ${ZERO_ALERT_USD_PER_DAY:.0f}) over the last 24h"})
    for label, k in (("total", "usdPerDay"), ("fees", "feesUsdPerDay")):
        if ("24h" in deltas and "7d" in deltas and not (deltas["24h"]["partial"] or deltas["7d"]["partial"])
                and deltas["7d"][k] > 0 and deltas["24h"][k] < DROP_ALERT_RATIO * deltas["7d"][k]):
            drop = 1 - deltas["24h"][k] / deltas["7d"][k]
            alerts.append({"type": "rate_drop" if label == "total" else "fees_rate_drop",
                           "usdPerDay24h": deltas["24h"][k], "usdPerDay7d": deltas["7d"][k], "dropPct": drop * 100,
                           "message": f"24h {label} earnings ${deltas['24h'][k]:.2f}/day are {drop * 100:.0f}% below the "
                                      f"7d rate ${deltas['7d'][k]:.2f}/day"})
    for a in alerts:
        logger.warning(f"[position] ALERT {a['type']}: {a['message']}")

    # keep ~daily points for ~10 days; a run within 12 h of the newest point replaces it
    if history and now_ts - int(history[-1]["asOf"]) < HISTORY_MIN_SPACING:
        history = history[:-1]
    history = [h for h in history + [point] if now_ts - int(h["asOf"]) <= HISTORY_MAX_AGE][-HISTORY_MAX_POINTS:]

    out["trailing"] = trailing
    out["feesOnly"] = {**_rates(fees_day_total, stake_usd, staked_iaero_usd, stakers_bps, "feesOnly"),
                       "basis": "since allocation", "trailing": fees_trailing}
    out["alerts"] = alerts
    out["history"] = history
    out["definitions"].update({
        "trailing": "24h / 7d rates from the change in per-gauge cumulative earnings since the history point closest to "
                    "24 h (20-36 h old) / 7 d (6-8 d old) before this run, valued at current prices; null until such a point exists",
        "feesOnly": "same figures counting trading fees only (no incentive programs)",
        "history": "~daily points (<= 10.5 d): per-gauge cumulative token amounts keyed chainId:gauge, claimed + unclaimed",
        "alerts": "gauge_no_earnings_24h (allocated gauge < $1/day over 24h), rate_drop / fees_rate_drop "
                  "(24h < 50% of 7d), negative_delta (cumulative fell: claims not scanned?)",
    })
    return out


def build_live(chain_readers: List[tuple], token_id: int, price_fetchers: Dict[int, object], staked_aero_raw: int,
               aero_price: float, staked_iaero_usd: float, stakers_bps: int = 8000,
               prev_live: Optional[dict] = None, now_ts: Optional[int] = None,
               first_allocation: Optional[int] = None) -> dict:
    """chain_readers: [(reader, registry_or_None)]. price_fetchers: {chainId: PriceFetcher for that chain}.
    A chain whose reads fail is reported in unmeasuredChains instead of failing the whole block."""
    prev_g, prev_history = {}, []
    if prev_live and int(prev_live.get("stakeId", -1)) == int(token_id):
        for g in prev_live.get("gauges") or []:
            prev_g.setdefault(int(g.get("chainId", 0)), []).append(g["gauge"])
        prev_history = prev_live.get("history") or []
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
                      unmeasured=unmeasured, prev_history=prev_history)
    logger.info(
        f"[position] stake #{token_id}: accrued=${live['accruedUSD']:.2f} over {live['elapsedDays']:.3f}d "
        f"-> ${live['usdPerDay']:.2f}/day, positionApr={live.get('positionAprPct')} "
        f"projectedStakerApy={live.get('projectedStakerApyPct')} measured={live['measuredShareOfAllocation']:.3f} "
        f"unpriced={len(live['unpricedTokens'])} feesOnly=${live['feesOnly']['usdPerDay']:.2f}/day "
        f"trailing24h={(live['trailing']['24h'] or {}).get('usdPerDay')} trailing7d={(live['trailing']['7d'] or {}).get('usdPerDay')} "
        f"alerts={len(live['alerts'])} history={len(live['history'])}"
    )
    return live


def staked_aero(reader, token_id: int, voting_escrow: str = VOTING_ESCROW) -> int:
    """Voting power of the stake (permanent stake: equals the AERO staked)."""
    return int(reader.many([(voting_escrow, "balanceOfNFT(uint256)", [token_id], ["uint256"])])[0] or 0)
