# position_earnings.py
"""
Real-time earnings of the protocol's Aero stake (veNFT, e.g. #1584): the `live` block of
data/estimated_rewards_usd.json, and the measured rate the headline apyPct comes from. Read-only.

Per chain (Base, Ethereum, Robinhood 4663; a chain whose reads fail is reported unmeasured):
  gauges   = LeafVoter.allocatedGauges(tokenId), plus the gauges of the previous live block, the stake's
             first-allocation gauges (FIRST_ALLOCATION_GAUGES, config) and every gauge the claims state remembers, so
             a re-vote (even one before the bot first ran) doesn't drop earnings on a gauge the stake left; plus any
             registered gauge whose VRM emitted a claim for the stake (address-less claim scan, where the RPC allows)
  VRM      = FactoryRegistry.gaugeToRewards(gauge) on Base, else gauge.votingRewardsManager()
  earned   = VRM.earnedFees(tokenId, maxCk)              (token0/token1; includes uncredited fees)
           + VRM.earnedIncentives(tokenId, programId, maxCk) for programId 1..incentiveCount()
           + claimed so far (ClaimFees / ClaimIncentives logs for tokenId), so the total is cumulative. The claims
             are scanned incrementally: per chain the last scanned block and the cumulative claimed amounts per VRM
             and token are kept (claimsState, data/live_state.json); a failed scan leaves them for the next run
  since    = LeafVoter.tokenStates(tokenId).lastAllocated, but never later than the stake's first
             allocation when known (lastAllocated moves on every re-vote while earnings stay on the VRM)
Valuation uses CURRENT prices. usdPerDay = accruedUSD / elapsed days (since allocation).
  positionAprPct        = usdPerDay*365 / (staked AERO * AERO price)            (the position's own yield)
  projectedStakerApyPct = usdPerDay*365 * stakers share / staked iAERO USD      (same denominator as apyPct)
readComplete: every chain read (claims scanned, gauge list and every gauge read) and every earned token priced; a
trailing window ends at the closest COMPLETE history point in its age range, and is complete when the current read is,
both points cover the same chains in full and nothing is left out.
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
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"         # same address on Base, Ethereum and Robinhood
DEFAULT_STAKE_ID = 1584
FIRST_ALLOCATION = {1584: 1792635063}                              # #1584 first allocated 2026-10-22 02:11:03 UTC
UNMEASURED_CHAINS: List[int] = []                                  # every chain #1584 votes on has an RPC
ROBINHOOD_CHAIN_ID = 4663
ROBINHOOD_RPC = "https://rpc.mainnet.chain.robinhood.com"          # env ROBINHOOD_RPC_URL
# Robinhood tokens DefiLlama may not price under robinhood:<address>: the DefiLlama key priced instead. Never guessed:
# a token neither priced nor mapped stays unpriced and the read is incomplete.
ROBINHOOD_PRICE_MAP = {
    "0x0bd7d308f8e1639fab988df18a8011f41eacad73": "ethereum:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0x5fc5360d0400a0fd4f2af552add042d716f1d168": "coingecko:global-dollar",                              # USDG
}
# #1584's gauges at its first allocation (22 Oct 2026; allocatedGauges(1584) checked on chain on all three chains, on
# Base also at the allocation block): measured even after a re-vote that happened before the bot first ran
FIRST_ALLOCATION_GAUGES = {1584: {
    8453: ["0x14018f5AFaeCA44BB49d5036267d836723B57c91", "0x347f2eEDD83Dc6b14116f0260403d67A21f47C30",
           "0x4262b2d1415345b98E656a56c2f12cDBb1118539", "0x46a9dCa72D78366571bE583aa69C1DC16E6889fB",
           "0x4A3B6A77B545584d870D4A6de446AAc4610c60D5", "0x5b14d6D194E49330647eB4717010aDe1B1B3f8B5",
           "0xb1b27a2fa4E67a6d0Ee1aA9De97c8b1DDF54FDD4", "0xd424BA8ca9d4E278753DE76651a0095451e65cD1",
           "0xFc8922E268CCcbe8160e5C1AD546Af9705Cf0A61"],
    1: ["0x430D74920F5BF2a6A2A27aF16Ab66Dfe77bffA2a"],
    4663: ["0xe033F4Bd3D7Ccf537A2F954eCDC8eB1218e3B7a6"],
}}
# LeafVoter.gaugeStates(gauge): (ceiling, claimed, lastSettlement, isRegistered, isActivated, surplus, lastIndex,
# lastTimeIndex, point (bias, slope, ts, permanentStakeBalance)), flattened (a static struct is encoded inline)
GAUGE_STATE_OUT = ["uint128", "uint128", "uint48", "bool", "bool", "uint128", "uint256", "uint256",
                   "int128", "int128", "uint48", "uint128"]
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

    def _ts(self, block: int) -> int:
        return int(self._retry(lambda: self.w3.eth.get_block(int(block)))["timestamp"])

    def block_at(self, ts: int) -> int:
        """The last block with timestamp <= ts (0 if none): a galloping search back from the pinned block, then a
        bisection, on block timestamps only (no block-time assumption: Robinhood makes 10 blocks a second)."""
        if int(ts) >= self.block_ts:
            return self.block
        hi, step = self.block, 1
        lo = max(0, hi - step)
        while lo > 0 and self._ts(lo) > int(ts):
            hi, step = lo, step * 2
            lo = max(0, hi - step)
        if lo == 0 and self._ts(0) > int(ts):
            return 0
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if self._ts(mid) <= int(ts):
                lo = mid
            else:
                hi = mid
        return lo

    def logs(self, addresses: Optional[List[str]], topics: list, from_block: int, to_block: Optional[int] = None,
             step: int = 10_000, min_step: int = 500, max_step: int = 1_000_000) -> Optional[list]:
        """All logs in [from_block, to_block (default: the pinned block)] from `addresses` (None: any contract), or
        None if the RPC refuses a range of min_step blocks (the caller then counts the claims as unknown). The range
        per call halves on errors (public RPCs cap it, e.g. 1000 blocks) and doubles after successes."""
        out, fb = [], int(from_block)
        tb_max = self.block if to_block is None else min(int(to_block), self.block)
        flt = {"topics": topics}
        if addresses is not None:
            flt["address"] = [self.w3.to_checksum_address(a) for a in addresses]
        while fb <= tb_max:
            tb = min(tb_max, fb + step - 1)
            try:
                out.extend(self._retry(lambda: self.w3.eth.get_logs(dict(flt, fromBlock=fb, toBlock=tb)), tries=3))
                fb = tb + 1
                step = min(max_step, step * 2)
            except Exception as e:
                if step > min_step:
                    step = max(min_step, step // 2)
                    continue
                logger.warning(f"[position] chain {self.chain_id}: eth_getLogs refused "
                               f"({'any address' if addresses is None else f'{len(addresses)} addresses'}): {str(e)[:120]}")
                return None
        return out


def _topic_int(t) -> int:
    return int(t.hex() if hasattr(t, "hex") else t, 16)


def _gauge_rows(reader, token_id: int, leaf_voter: str, registry: Optional[str], gauges: List[str],
                allocated: List[str]) -> tuple:
    """(rows, unread): per gauge its VRM (FactoryRegistry.gaugeToRewards on Base, else the gauge's own pointer), pool
    and the stake's allocation; gauges whose VRM can't be resolved are listed in unread."""
    per = []
    for g in gauges:
        per += [(leaf_voter, "allocations(uint256,address)", [token_id, g], ["uint128"]),
                (g, "votingRewardsManager()", [], ["address"]),
                (g, "pool()", [], ["address"]),             # CL gauges
                (g, "stakingToken()", [], ["address"])]     # v2 gauges (the pool is the LP token)
        if registry:
            per.append((registry, "gaugeToRewards(address)", [g], ["address"]))
    res = reader.many(per)
    k = 5 if registry else 4
    rows = []
    for i, g in enumerate(gauges):
        alloc, vrm_g, pool, lp = res[i * k:i * k + 4]
        vrm_r = res[i * k + 4] if registry else None
        vrm = vrm_r if vrm_r and vrm_r != ZERO else vrm_g
        rows.append({"gauge": g, "vrm": (vrm or "").lower(), "pool": (pool or lp or "").lower(),
                     "allocation": int(alloc or 0), "active": g in allocated})
    unread = [r["gauge"] for r in rows if not r["vrm"] or r["vrm"] == ZERO]    # no VRM resolved: earnings unknown
    return [r for r in rows if r["vrm"] and r["vrm"] != ZERO], unread


def _registered_vrms(reader, leaf_voter: str, registry: Optional[str], vrms: List[str]) -> Dict[str, str]:
    """{vrm: gauge} for the contracts in `vrms` that are the voting-rewards manager of a gauge the LeafVoter
    registered (VRM.gauge() -> gauge, whose VRM (registry on Base, else its own pointer) is that contract). Anything
    else that emitted a claim event for the stake (a spoof, another protocol) is left out."""
    gs = reader.many([(v, "gauge()", [], ["address"]) for v in vrms])
    cand = {v: g.lower() for v, g in zip(vrms, gs) if g and g != ZERO}
    per = []
    for v, g in cand.items():
        per += [(g, "votingRewardsManager()", [], ["address"]),
                (registry or "", "gaugeToRewards(address)", [g], ["address"]),
                (leaf_voter, "gaugeStates(address)", [g], GAUGE_STATE_OUT)]
    res = reader.many(per)
    out = {}
    for i, (v, g) in enumerate(cand.items()):
        own, reg, st = res[i * 3:i * 3 + 3]
        vrm = reg if reg and reg != ZERO else own
        if vrm and vrm.lower() == v and st and st[3]:              # st[3]: isRegistered
            out[v] = g
    return out


def read_chain_position(reader, token_id: int, leaf_voter: str = LEAF_VOTER, registry: Optional[str] = None,
                        extra_gauges: tuple = (), max_checkpoints: int = MAX_CHECKPOINTS,
                        first_allocation: Optional[int] = None, claims_state: Optional[dict] = None) -> dict:
    """Raw on-chain earnings of `token_id` on one chain (no prices).
    Gauges read: allocatedGauges now, extra_gauges (the previous live block's, the first-allocation ones from
    config) and every gauge this chain's claims state remembers, so a gauge the stake left keeps being measured.
    claims_state: this chain's {"since", "block", "blockTimestamp", "gauges": [gauge], "vrms": {vrm: {"fees":
    {token: raw}, "incentives": {token: raw}}}} from the previous run: claims are scanned only after its block (a VRM
    new to it: from `since`). The scan is address-less where the RPC allows it, so a registered gauge's VRM that paid
    the stake a claim joins the gauges read (discovery). The result's claimsState is the updated one, or the given
    one (plus the gauges seen) if a scan failed (claimsScanned False)."""
    gauges, state = reader.many([
        (leaf_voter, "allocatedGauges(uint256)", [token_id], ["address[]"]),
        (leaf_voter, "tokenStates(uint256)", [token_id], ["address", "uint48", "bool", "uint128"]),
    ])
    allocated = [g.lower() for g in (gauges or [])]
    remembered = (claims_state.get("gauges") or []) if isinstance(claims_state, dict) else []
    all_gauges = list(dict.fromkeys(allocated + [str(g).lower() for g in list(extra_gauges) + list(remembered)]))
    rows, unread = _gauge_rows(reader, token_id, leaf_voter, registry, all_gauges, allocated)

    # claims so far (cumulative = claimed + unclaimed), scanned incrementally
    first = first_allocation if first_allocation is not None else FIRST_ALLOCATION.get(token_id)
    last_alloc = int(state[1]) if state else 0
    since = min(x for x in (last_alloc, first) if x) if (last_alloc or first) else reader.block_ts
    prev = claims_state if (isinstance(claims_state, dict) and claims_state.get("since") == int(since)
                            and isinstance(claims_state.get("block"), int)) else None
    cum = {v: {"fees": dict((d or {}).get("fees") or {}), "incentives": dict((d or {}).get("incentives") or {})}
           for v, d in ((prev or {}).get("vrms") or {}).items()}
    known = sorted(cum)
    tid_topic = "0x" + int(token_id).to_bytes(32, "big").hex()
    topics = [[CLAIM_FEES_TOPIC, CLAIM_INCENTIVES_TOPIC], tid_topic]
    emitter = lambda lg: str(lg["address"]).lower()
    claims: Optional[list] = []
    discovered: List[str] = []
    if prev and prev["block"] > reader.block:
        # this RPC is behind the last run: claims after its block would count twice (claimed + unclaimed)
        logger.warning(f"[position] chain {reader.chain_id}: block {reader.block} is behind the claims state "
                       f"({prev['block']}); claims unknown this run")
        claims = None
    else:
        lo = prev["block"] + 1 if prev else reader.block_at(since)
        anylogs = reader.logs(None, topics, lo) if lo <= reader.block else []
        if anylogs:
            # claims for the stake from VRMs not read: a registered gauge's VRM joins (the stake earned there)
            unknown = sorted({emitter(lg) for lg in anylogs} - set(known) - {r["vrm"] for r in rows})
            found = _registered_vrms(reader, leaf_voter, registry, unknown) if unknown else {}
            for v in unknown:
                if v not in found:
                    logger.info(f"[position] chain {reader.chain_id}: claim event from {v} (not a registered "
                                f"gauge's VRM) ignored")
            add = [g for g in dict.fromkeys(found.values()) if g not in all_gauges]
            if add:
                logger.warning(f"[position] chain {reader.chain_id}: gauges found from the stake's claims, now "
                               f"measured: {add}")
                more, more_unread = _gauge_rows(reader, token_id, leaf_voter, registry, add, allocated)
                rows, unread, all_gauges, discovered = rows + more, unread + more_unread, all_gauges + add, add
        new = sorted({r["vrm"] for r in rows} - set(known))
        if anylogs is not None:
            # every claim from lo on is in anylogs: known VRMs from it; new ones also need [since, lo)
            claims = [lg for lg in anylogs if emitter(lg) in set(known) | set(new)]
            if new and prev:
                got = reader.logs(new, topics, reader.block_at(since), to_block=lo - 1)
                claims = None if got is None else claims + got
        else:
            # the RPC wants an address (e.g. publicnode on Ethereum): the VRMs read, no discovery
            if known and lo <= reader.block:
                got = reader.logs(known, topics, lo)
                claims = None if got is None else got
            if new and claims is not None:
                got = reader.logs(new, topics, reader.block_at(since))
                claims = None if got is None else claims + got

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
        fees = f2 if (r["truncated"] or f1 is None) else f1
        r["fees"] = {r["token0"]: int(fees[0]), r["token1"]: int(fees[1])} if fees and r["token0"] and r["token1"] else {}
        r["readOk"] = bool(fees is not None and r["token0"] and r["token1"] and n is not None)   # every read answered
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
            r["readOk"] = False
            continue
        trunc = e1 is not None and e2 is not None and e1 != e2
        amount = e2 if (trunc or e1 is None) else e1
        r["readOk"] = r["readOk"] and amount is not None
        r["truncated"] = r["truncated"] or trunc
        r["incentives"].append({"programId": pid, "token": inc[0].lower(), "amount": int(amount or 0),
                                "start": int(inc[3]), "end": int(inc[4])})

    by_vrm = {r["vrm"]: r for r in rows}
    parsed = []
    for lg in claims or []:
        vrm = str(lg["address"]).lower()
        topic0 = "0x" + (lg["topics"][0].hex() if hasattr(lg["topics"][0], "hex") else lg["topics"][0]).removeprefix("0x")
        amount = _topic_int(lg["data"]) if lg["data"] not in (b"", "0x") else 0
        is_fee = topic0 == CLAIM_FEES_TOPIC
        if is_fee:
            token = "0x" + format(_topic_int(lg["topics"][3]), "040x")
        else:
            pid = _topic_int(lg["topics"][3])
            r = by_vrm.get(vrm)
            token = next((x["token"] for x in (r or {}).get("incentives", []) if x["programId"] == pid), None)
            if token is None:
                inc = reader.many([(vrm, "incentive(uint256)", [pid],
                                    ["address", "uint256", "uint256", "uint48", "uint48", "address"])])[0]
                token = inc[0].lower() if inc else None
        if not token:
            # an incentive claim whose token can't be read: rescanned next run rather than lost for good
            logger.warning(f"[position] chain {reader.chain_id}: claim of program {pid} on {vrm} unresolved; "
                           f"claims unknown this run")
            claims, parsed = None, []
            break
        parsed.append((vrm, is_fee, token, amount))
    for vrm, is_fee, token, amount in parsed:
        kind = cum.setdefault(vrm, {"fees": {}, "incentives": {}})["fees" if is_fee else "incentives"]
        kind[token] = int(kind.get(token, 0)) + amount
    for r in rows:
        c = cum.get(r["vrm"]) or {"fees": {}, "incentives": {}}
        r["claimedFees"] = {t: int(a) for t, a in c["fees"].items()}
        r["claimedIncentives"] = {t: int(a) for t, a in c["incentives"].items()}
        r["claimed"] = {}
        for t, a in list(r["claimedFees"].items()) + list(r["claimedIncentives"].items()):
            r["claimed"][t] = r["claimed"].get(t, 0) + a
    seen = sorted(set(all_gauges))
    if claims is not None:
        for r in rows:                                  # scanned: recorded even without claims (not rescanned)
            cum.setdefault(r["vrm"], {"fees": {}, "incentives": {}})
        new_state = {"since": int(since), "block": int(reader.block), "blockTimestamp": int(reader.block_ts),
                     "gauges": seen,
                     "vrms": {v: {"fees": {t: int(a) for t, a in d["fees"].items()},
                                  "incentives": {t: int(a) for t, a in d["incentives"].items()}} for v, d in cum.items()}}
    else:
        new_state = dict(prev or {}, gauges=seen)       # the claims are retried; the gauges seen are remembered

    return {"chainId": reader.chain_id, "block": reader.block, "blockTimestamp": reader.block_ts,
            "lastAllocated": last_alloc, "since": int(since), "chainAllocation": int(state[3]) if state else 0,
            "claimsScanned": claims is not None, "gaugeListRead": gauges is not None,
            "unreadGauges": unread + [r["gauge"] for r in rows if not r["readOk"]], "gauges": rows,
            "discoveredGauges": discovered, "claimsState": new_state}


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
# A point lists only chains whose claims were scanned and whose gauge list was read ("chains"); on those chains it
# holds every gauge read in full, and lists the ones whose reads failed in "unread". A point with no such chain is
# not recorded. So an end of a window never lacks claims, and a gauge missing from the older point counts from zero
# only if the stake re-allocated on that chain after that point (otherwise it is left out and the window is partial).
DAY_SEC = 86400
EPOCH_SEC = 7 * DAY_SEC                 # epochs: weeks from Thursday 00:00 UTC (unix time 0 was a Thursday)
WINDOWS = {"24h": (20 * 3600, 36 * 3600, 24 * 3600),          # (min age, max age, target age) of the snapshot used
           "7d": (6 * DAY_SEC, 8 * DAY_SEC, 7 * DAY_SEC)}
HISTORY_MAX_AGE = int(10.5 * 86400)
HISTORY_MAX_POINTS = 24
HISTORY_MIN_SPACING = 12 * 3600         # points >= 12 h apart: the newest is replaced while it is closer to the one before
DROP_ALERT_RATIO = 0.5                  # 24h rate below 50% of the 7d rate -> alert
ZERO_ALERT_USD_PER_DAY = 1.0            # an allocated gauge under $1/day over 24h counts as earning nothing


def _sig(x: float) -> float:
    return float(f"{x:.8g}")


def pick_snapshot(history: List[dict], now_ts: int, window: str) -> Optional[dict]:
    """The point closest to the window's target age among those [min, max] old that were read in full (complete, no
    unread gauge): an incomplete point never ends a window while a complete one is in range (review 8 M-1)."""
    lo, hi, target = WINDOWS[window]
    cands = [h for h in history or [] if lo <= now_ts - int(h.get("asOf", 0)) <= hi
             and h.get("complete") and not h.get("unread")]
    return min(cands, key=lambda h: abs(now_ts - int(h["asOf"]) - target)) if cands else None


def window_delta(cur: dict, snap: dict, price: Callable[[int, str], float],
                 last_allocated: Optional[Dict[int, int]] = None) -> Optional[dict]:
    """USD earned between `snap` and `cur` (both history points), per gauge and in total, fees apart.
    last_allocated: {chainId: the stake's latest allocation time} at `cur`. None if the points share no chain."""
    days = (int(cur["asOf"]) - int(snap["asOf"])) / 86400.0
    per_gauge, total, fees, negative = {}, 0.0, 0.0, []
    snap_g = snap.get("gauges") or {}
    snap_chains = set(snap.get("chains") or {int(k.split(":")[0]) for k in snap_g})
    cur_chains = set(cur.get("chains") or {int(k.split(":")[0]) for k in cur["gauges"]})
    common = snap_chains & cur_chains
    if not common:
        return None
    partial = snap_chains != cur_chains          # a chain measured in only one of the two points is left out
    snap_unread = set(snap.get("unread") or [])
    for key in snap_g:                           # in the older point but not read now: its earnings are missing
        if int(key.split(":")[0]) in common and key not in cur["gauges"]:
            partial = True
    for key, g in cur["gauges"].items():
        cid = int(key.split(":")[0])
        if cid not in common:
            continue
        if key not in snap_g and (key in snap_unread or not g.get("active", True) or
                                  int((last_allocated or {}).get(cid, 0)) <= int(snap["asOf"])):
            # read failed then, the stake has not re-allocated since, or it isn't allocated there now (a gauge first
            # read now, e.g. found from a claim, may hold earnings from before the snapshot): its whole cumulative
            # would count as earned
            partial = True
            continue
        old = snap_g.get(key) or {}
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
               prev_history: Optional[List[dict]] = None, excluded: Optional[Dict[int, List[str]]] = None) -> dict:
    """Pure: price the raw per-chain reads into the `live` block (plus trailing windows over prev_history).
    excluded {chainId: [token]}: tokens valued at 0 on purpose (an untrusted DEX price), listed, not unpriced."""
    now_ts = int(now_ts if now_ts is not None else time.time())
    stake = staked_aero_raw / 1e18 if staked_aero_raw else 0.0
    gauges_out, unpriced = [], set()
    accrued_total = usd_day_total = 0.0
    split_total = {"feesUSD": 0.0, "incentivesUSD": 0.0, "claimedUSD": 0.0}
    measured_alloc = 0
    fees_day_total = 0.0
    # history point: chains whose claims were scanned and gauge list read; gauges read in full on them
    recorded = {c["chainId"] for c in chains if c["claimsScanned"] and c.get("gaugeListRead", True)}
    point = {"asOf": now_ts, "chains": sorted(recorded), "accruedUSD": 0.0, "feesCumUSD": 0.0, "gauges": {},
             "unread": sorted(f"{c['chainId']}:{g}" for c in chains if c["chainId"] in recorded
                              for g in c.get("unreadGauges", []))}

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
                if px <= 0 and t not in (excluded or {}).get(cid, []):
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
            if cid in recorded and r.get("readOk", True):
                point["gauges"][f"{cid}:{r['gauge']}"] = {
                    "active": bool(r.get("active", True)),
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
    unmeasured_chains = sorted(set(UNMEASURED_CHAINS if unmeasured is None else unmeasured))
    read_complete = bool(chains) and not unmeasured_chains and not unpriced and all(
        c["claimsScanned"] and c.get("gaugeListRead", True) and not c.get("unreadGauges") for c in chains)
    point["complete"] = read_complete
    point["lastAllocated"] = {str(c["chainId"]): int(c.get("lastAllocated") or 0) for c in chains}
    out = {
        "method": "live_position",
        "stale": False,
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
        "unmeasuredChains": unmeasured_chains,
        "readComplete": read_complete,
        "chains": [{"chainId": c["chainId"], "block": c["block"], "blockTimestamp": c["blockTimestamp"],
                    "since": c["since"], "lastAllocated": c["lastAllocated"],
                    "allocationAero": c["chainAllocation"] / 1e18, "claimsScanned": c["claimsScanned"],
                    "gaugeListRead": c.get("gaugeListRead", True), "unreadGauges": sorted(c.get("unreadGauges", []))}
                   for c in chains],
        "gauges": gauges_out,
        "unpricedTokens": sorted(unpriced),
        "excludedTokens": sorted(f"{cid}:{t}" for cid, toks in (excluded or {}).items() for t in toks),
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
    last_allocated = {c["chainId"]: int(c.get("lastAllocated") or 0) for c in chains}
    for w in WINDOWS:
        snap = pick_snapshot(history, now_ts, w)
        d = window_delta(point, snap, price, last_allocated) if snap else None
        if not d:
            trailing[w] = fees_trailing[w] = None
            continue
        deltas[w] = d
        meta_w = {"snapshotAsOf": int(snap["asOf"]), "snapshotAgeHours": round((now_ts - int(snap["asOf"])) / 3600.0, 2),
                  "claimsComplete": claims_ok, "partial": d["partial"],
                  # both ends in full: this read complete, the snapshot too, nothing left out between them, and no
                  # cumulative amount that fell (a claim not seen)
                  "complete": bool(read_complete and snap.get("complete") and not snap.get("unread")
                                   and not d["partial"] and not d["negative"])}
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

    # points >= 12 h apart for ~10 days, whatever the run cadence: the newest point is provisional (the next run
    # replaces it) while it is under 12 h newer than the point before it, except the first point of an epoch
    # (Thursday 00:00 UTC), kept for yield_history (epoch_rate). A run with no chain fully measured (claims refused)
    # records nothing and keeps the newest point.
    if point["chains"]:
        if (len(history) >= 2 and int(history[-1]["asOf"]) - int(history[-2]["asOf"]) < HISTORY_MIN_SPACING
                and int(history[-1]["asOf"]) // EPOCH_SEC == int(history[-2]["asOf"]) // EPOCH_SEC):
            history = history[:-1]
        history = history + [point]
    history = [h for h in history if now_ts - int(h["asOf"]) <= HISTORY_MAX_AGE][-HISTORY_MAX_POINTS:]

    out["trailing"] = trailing
    out["feesOnly"] = {**_rates(fees_day_total, stake_usd, staked_iaero_usd, stakers_bps, "feesOnly"),
                       "basis": "since allocation", "trailing": fees_trailing}
    out["alerts"] = alerts
    out["history"] = history
    out["definitions"].update({
        "trailing": "24h / 7d rates from the change in per-gauge cumulative earnings since the complete history point "
                    "closest to 24 h (20-36 h old) / 7 d (6-8 d old) before this run, valued at current prices; null until "
                    "such a point exists or when the two points share no fully measured chain; partial when a chain or "
                    "gauge is left out",
        "feesOnly": "same figures counting trading fees only (no incentive programs)",
        "history": "points >= 12 h apart (<= 10.5 d; plus the first of each epoch): per-gauge cumulative token amounts "
                   "keyed chainId:gauge, claimed + unclaimed; "
                   "only chains whose claims were scanned, only gauges read in full (failed reads listed in unread); "
                   "complete when that run's read was",
        "readComplete": "every chain read (claims scanned, gauge list and every gauge read) and every earned token priced",
        "stale": "true when this block could not be rebuilt and the previous one was kept as is",
        "alerts": "gauge_no_earnings_24h (allocated gauge < $1/day over 24h), rate_drop / fees_rate_drop "
                  "(24h < 50% of 7d), negative_delta (cumulative fell: claims not scanned?)",
    })
    return out


def build_live(chain_readers: List[tuple], token_id: int, price_fetchers: Dict[int, object], staked_aero_raw: int,
               aero_price: float, staked_iaero_usd: float, stakers_bps: int = 8000,
               prev_live: Optional[dict] = None, now_ts: Optional[int] = None,
               first_allocation: Optional[int] = None, claims_state: Optional[dict] = None,
               unreachable: Optional[List[int]] = None) -> dict:
    """chain_readers: [(reader, registry_or_None)]. price_fetchers: {chainId: PriceFetcher for that chain}.
    A chain whose reads fail, or listed in `unreachable` (no reader could be made), is reported in unmeasuredChains
    instead of failing the whole block (the read is then incomplete).
    The prices used are returned under "_prices" ({chainId: {token: usd}}; the caller drops the key).
    claims_state: {"stakeId", "chains": {"<chainId>": per-chain claims state}} from the previous run; the updated one
    is returned under the live block's "_claimsState" key (the caller stores it and drops the key).
    A DEX price counts only under realized_yield's trusted-DEX rule; other DEX-priced tokens are excluded (valued 0)."""
    from realized_yield import trusted_dex_tokens, DEX_TRUSTED_DEPTH_USD
    import os
    trusted = trusted_dex_tokens()
    depth_min = float(os.environ.get("DEX_TRUSTED_DEPTH_USD") or DEX_TRUSTED_DEPTH_USD)
    cs_chains = {}
    if isinstance(claims_state, dict) and int(claims_state.get("stakeId", -1)) == int(token_id):
        cs_chains = dict(claims_state.get("chains") or {})
    prev_g, prev_history = {}, []
    if prev_live and int(prev_live.get("stakeId", -1)) == int(token_id):
        for g in prev_live.get("gauges") or []:
            prev_g.setdefault(int(g.get("chainId", 0)), []).append(g["gauge"])
        prev_history = prev_live.get("history") or []
    chains, meta, prices, excluded = [], {}, {}, {}
    unmeasured = list(UNMEASURED_CHAINS) + [int(c) for c in (unreachable or [])]
    for reader, registry in chain_readers:
        try:
            seed = FIRST_ALLOCATION_GAUGES.get(int(token_id), {}).get(reader.chain_id, [])
            ch = read_chain_position(reader, token_id, registry=registry, first_allocation=first_allocation,
                                     extra_gauges=tuple(prev_g.get(reader.chain_id, [])) + tuple(seed),
                                     claims_state=cs_chains.get(str(reader.chain_id)))
            toks = set()
            for r in ch["gauges"]:
                toks |= set(r["fees"]) | {x["token"] for x in r["incentives"]} | set(r["claimed"]) | {r["token0"], r["token1"]}
            toks.discard("")
            meta[reader.chain_id] = token_meta(reader, sorted(toks))
            pf = price_fetchers.get(reader.chain_id)
            got = pf.fetch_batch(sorted(toks)) if (pf and toks) else {}
        except Exception as e:
            logger.warning(f"[position] chain {reader.chain_id} read failed ({str(e)[:160]}); reported as unmeasured")
            unmeasured.append(reader.chain_id)
            continue
        if ch.get("claimsState") is not None:
            cs_chains[str(reader.chain_id)] = ch["claimsState"]
        chains.append(ch)
        prices[reader.chain_id] = {}
        for t in toks:
            e = got.get(t) or {}
            px = float(e.get("priceUsd", 0.0) or 0.0)
            if e.get("source") == "dex" and not (t in trusted and isinstance(e.get("dexDepthUsd"), (int, float))
                                                  and e["dexDepthUsd"] >= depth_min):
                excluded.setdefault(reader.chain_id, []).append(t)          # untrusted DEX price: left out
                px = 0.0
            prices[reader.chain_id][t] = px
    live = value_live(chains, meta, prices, token_id, staked_aero_raw, aero_price, staked_iaero_usd, stakers_bps, now_ts,
                      unmeasured=unmeasured, prev_history=prev_history, excluded=excluded)
    live["_claimsState"] = {"stakeId": int(token_id), "chains": cs_chains}
    live["_prices"] = prices
    logger.info(
        f"[position] stake #{token_id}: accrued=${live['accruedUSD']:.2f} over {live['elapsedDays']:.3f}d "
        f"-> ${live['usdPerDay']:.2f}/day, positionApr={live.get('positionAprPct')} "
        f"projectedStakerApy={live.get('projectedStakerApyPct')} measured={live['measuredShareOfAllocation']:.3f} "
        f"unpriced={len(live['unpricedTokens'])} feesOnly=${live['feesOnly']['usdPerDay']:.2f}/day "
        f"trailing24h={(live['trailing']['24h'] or {}).get('usdPerDay')} trailing7d={(live['trailing']['7d'] or {}).get('usdPerDay')} "
        f"alerts={len(live['alerts'])} history={len(live['history'])} readComplete={live['readComplete']} "
        f"unmeasured={live['unmeasuredChains']}"
    )
    return live


EPOCH_POINT_TOLERANCE = 6 * 3600        # a history point this close to an epoch boundary stands for it


def epoch_rate(history: List[dict], start: int, end: int, price: Callable[[int, str], float],
               tolerance: int = EPOCH_POINT_TOLERANCE) -> Optional[dict]:
    """Measured earnings between the epoch boundaries `start` and `end`: the complete history points closest to each
    (within `tolerance`), their per-gauge cumulative delta valued at `price`. None unless both exist and nothing is
    left out between them ({"usdPerDay", "from", "to", "days"} otherwise)."""
    def near(ts):
        c = [h for h in history or [] if isinstance(h, dict) and h.get("complete") and not h.get("unread")
             and abs(int(h.get("asOf", 0)) - int(ts)) <= tolerance]
        return min(c, key=lambda h: abs(int(h["asOf"]) - int(ts))) if c else None
    a, b = near(start), near(end)
    if not a or not b or int(b["asOf"]) <= int(a["asOf"]):
        return None
    d = window_delta(b, a, price, {int(k): int(v) for k, v in (b.get("lastAllocated") or {}).items()})
    if not d or d["partial"]:
        return None
    return {"usdPerDay": d["usdPerDay"], "from": int(a["asOf"]), "to": int(b["asOf"]), "days": d["days"]}


def staked_aero(reader, token_id: int, voting_escrow: str = VOTING_ESCROW) -> int:
    """Voting power of the stake (permanent stake: equals the AERO staked)."""
    return int(reader.many([(voting_escrow, "balanceOfNFT(uint256)", [token_id], ["uint256"])])[0] or 0)
