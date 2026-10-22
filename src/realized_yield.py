# realized_yield.py
"""
Realized staking yield for data/estimated_rewards_usd.json and data/yield_history.json
(replaces the legacy EnhancedOptimizedVotesKeeper estimate and the rewards keeper's yield snapshot).

Epoch E (weeks start Thursday 00:00 UTC, E = ts // WEEK * WEEK) is chosen by mode:
  latest_funded  (default) newest epoch with funding in epochs.json: the current epoch once the
                 Thursday 00:01 funding has landed, else the previous one. Older than 2 weeks -> 0.
  last_completed the most recent epoch whose week has ended.
  fundedUSD      = sum over tokens of rewardsForEpoch(token, E) * current USD price
  stakedUSD      = staked iAERO at E's start (the distributor's payout denominator) * iAERO price
  weeklyYieldPct = fundedUSD / stakedUSD * 100
  apyPct         = weeklyYieldPct * 52            (simple annualisation, no compounding)

Prices are CURRENT prices from PriceFetcher, not prices at funding time.
Not published (main.py logs and keeps the previous files) when sanity_problems() finds anything (apyPct NaN,
negative or > 500%; AERO or iAERO unpriced; a zero USD stake). When dex_guard_problem() finds DEX-priced funded
tokens inflating apyPct, main.py keeps the previous figures flagged stale (live and yield_history still update).
yield_history gets an epoch's entry only once that epoch has ended (main.py), so partial weeks never become references.
Readers of estimated_rewards_usd.json: TwitterBot (apyPct), DefiLlama yield-server iaero-protocol
(apyPct, tvlUSD_1e18), iaero-frontend (stakersWeeklyUSD_1e18, estimatedWeeklyUSD_1e18).
All legacy fields are kept with the same names and units; new fields are only added.
"""
import json
import math
import statistics
import time
import logging
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from typing import Callable, Dict, List, Optional

getcontext().prec = 60

logger = logging.getLogger(__name__)

WEEK = 7 * 24 * 60 * 60
WEEKS_PER_YEAR = 52
E18 = 10 ** 18
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
WETH_ADDRESS = "0x4200000000000000000000000000000000000006"
AERO_ADDRESS = "0x3f5bF3EdAc59d650D8fDf9657a71F2f904A3a4Ee"   # Aero AERO (post-migration)
IAERO_ADDRESS = "0x81034Fb34009115F215f5d5F564AAc9FfA46a1Dc"

EPOCH_MODES = ("latest_funded", "last_completed")
STALE_AFTER_SEC = 2 * WEEK      # latest funded epoch older than this -> publish 0, not a stale figure
MAX_SANE_APY_PCT = 500.0        # above this, don't publish (likely a bad price), log and skip
MAX_APY_RISE = 3.0              # apyPct above 3x the reference only because of DEX-priced tokens -> keep the previous figures
DEX_MAX_FUNDED_SHARE = 0.5      # DEX-priced tokens above half of the funded USD -> keep the previous figures
REFERENCE_EPOCHS = 4            # reference apyPct = median of the newest <= 4 earlier-epoch yield_history entries

# Split of harvested rewards (RewardsHarvesterV2.processAndDistribute): 80% goes to the
# EpochStakingDistributor, so the realized funding IS the stakers' share.
SPLIT_BPS = {"protocol": 1000, "peg": 1000, "stakers": 8000}
SPLIT_DENOM = 10_000

DIST_ABI = [
    {"inputs":[{"internalType":"address","name":"token","type":"address"},
               {"internalType":"uint256","name":"epochId","type":"uint256"}],
     "name":"rewardsForEpoch","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"epochId","type":"uint256"}],
     "name":"supplySnapshotAtEpochStart","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[{"internalType":"uint256","name":"epochId","type":"uint256"}],
     "name":"totalSupplyAtEpochStart","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"totalStaked","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
     "stateMutability":"view","type":"function"},
    {"inputs":[],"name":"iAERO","outputs":[{"internalType":"address","name":"","type":"address"}],
     "stateMutability":"view","type":"function"},
]


def epoch_start(ts: int) -> int:
    return (int(ts) // WEEK) * WEEK


def last_completed_epoch(now_ts: int) -> int:
    """The most recent epoch whose week has fully ended."""
    return epoch_start(now_ts) - WEEK


def latest_funded_epoch(epochs_doc: dict, now_ts: int) -> Optional[int]:
    """Newest epoch (not in the future) with funded tokens in epochs.json (RewardFunded only fires for amount > 0)."""
    cur = epoch_start(now_ts)
    funded = [int(k) for k, v in (epochs_doc.get("epochs") or {}).items()
              if str(k).isdigit() and int(k) <= cur and (v or {}).get("tokens")]
    return max(funded) if funded else None


def select_epoch(epochs_doc: dict, now_ts: int, mode: str = "latest_funded") -> tuple:
    """Return (epoch, stale). stale=True: the latest funded epoch is older than STALE_AFTER_SEC -> publish 0."""
    if mode == "last_completed":
        return last_completed_epoch(now_ts), False
    ep = latest_funded_epoch(epochs_doc, now_ts)
    if ep is None:
        return last_completed_epoch(now_ts), False
    return ep, (int(now_ts) - ep) > STALE_AFTER_SEC


def _int(x) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return 0


def sanity_problems(payload: dict) -> List[str]:
    """Reasons not to publish `payload` (empty -> publishable). Fields missing from `payload` aren't checked."""
    out = []
    apy = payload.get("apyPct")
    if not (isinstance(apy, (int, float)) and math.isfinite(apy) and 0 <= apy <= MAX_SANE_APY_PCT):
        out.append(f"apyPct={apy} is NaN, negative or above {MAX_SANE_APY_PCT}%")
    # core prices: a failed AERO / iAERO price would publish apyPct 0 and tvlUSD 0
    if "aeroPrice_1e18" in payload and _int(payload["aeroPrice_1e18"]) <= 0:
        out.append("AERO is unpriced")
    if payload.get("usedFallbackPrice") or ("iaeroPrice_1e18" in payload and _int(payload["iaeroPrice_1e18"]) <= 0):
        out.append("iAERO is unpriced")
    if _int(payload.get("stakedAtEpochStart_1e18")) > 0 and _int(payload.get("stakedUSD_1e18", 1)) <= 0:
        out.append("stakedUSD is 0 with a non-zero stake")
    if _int(payload.get("totalStaked_1e18")) > 0 and _int(payload.get("tvlUSD_1e18", 1)) <= 0:
        out.append("tvlUSD is 0 with a non-zero stake")
    return out


def is_sane_apy(payload: dict) -> bool:
    return not sanity_problems(payload)


def _positive(x) -> bool:
    return isinstance(x, (int, float)) and math.isfinite(x) and x > 0


def reference_apy(history_doc: Optional[dict], epoch: int) -> Optional[tuple]:
    """(median apyPct, [epochs]) of the newest REFERENCE_EPOCHS yield_history entries for epochs before `epoch` with
    apyPct > 0, or None. yield_history only gets completed epochs, so a partial week is never part of it."""
    series = history_doc.get("series") if isinstance(history_doc, dict) else None
    older = sorted((x for x in (series if isinstance(series, list) else [])
                    if isinstance(x, dict) and _int(x.get("epoch")) < int(epoch) and _positive(x.get("apyPct"))),
                   key=lambda x: _int(x.get("epoch")))[-REFERENCE_EPOCHS:]
    if not older:
        return None
    return float(statistics.median(float(x["apyPct"]) for x in older)), [_int(x.get("epoch")) for x in older]


def dex_guard_problem(payload: dict, history_doc: Optional[dict], max_rise: float = MAX_APY_RISE) -> Optional[str]:
    """
    Reason to keep the previous figures because DEX-priced funded tokens (PriceFetcher's on-chain fallback, the H-1
    risk) look like they inflate payload's apyPct, else None:
      - DEX-priced funded value is more than DEX_MAX_FUNDED_SHARE of the funded USD; or
      - apyPct is above max_rise x the reference (reference_apy) while apyPct without the DEX-priced tokens is not.
    A rise that is there without the DEX-priced tokens is published; no reference -> no ratio check.
    max_rise <= 0 disables both checks.
    """
    if not max_rise or max_rise <= 0:
        return None
    funded = _int(payload.get("fundedUSD_1e18")) / E18
    dex = _int(payload.get("dexFundedUSD_1e18")) / E18
    tokens = payload.get("dexPricedTokens") or []
    if funded > 0 and dex > DEX_MAX_FUNDED_SHARE * funded:
        return (f"DEX-priced tokens {tokens} are {dex / funded:.0%} of the funded ${funded:,.2f} "
                f"(more than {DEX_MAX_FUNDED_SHARE:.0%})")
    ref = reference_apy(history_doc, _int(payload.get("epoch")))
    apy = payload.get("apyPct")
    if ref is None or not isinstance(apy, (int, float)):
        return None
    limit = max_rise * ref[0]
    if not apy > limit:
        return None
    apy_without_dex = apy * (funded - dex) / funded if funded > 0 else apy
    if apy_without_dex > limit:
        return None                     # the rise is there without DEX-priced tokens: not a DEX price artefact
    return (f"apyPct {apy:.2f}% is above {max_rise:g}x the reference {ref[0]:.2f}% (median of yield_history epochs "
            f"{ref[1]}) only because of DEX-priced tokens {tokens} (${dex:,.2f}; apyPct without them "
            f"{apy_without_dex:.2f}%)")


def _to_1e18(x: Decimal) -> str:
    return str(int(x * E18))


def _human(x: Decimal) -> str:
    return f"{x:.4f}"


def compute_realized(
    epoch: int,
    funded: List[dict],
    staked_at_start_raw: int,
    total_staked_raw: int,
    iaero_price: float,
    aero_price: float,
    distributor: str = "",
    now_ts: Optional[int] = None,
    epoch_mode: str = "latest_funded",
    stale: bool = False,
) -> dict:
    """
    Pure computation of the estimated_rewards_usd.json payload.
    funded: [{"address", "amount" (raw int), "decimals", "priceUsd"}] for epoch `epoch`.
    stale=True publishes 0 for `epoch` (its funding is too old to be a current yield).
    """
    if stale:
        funded = []
    now_ts = int(now_ts if now_ts is not None else time.time())

    aero_px = Decimal(str(aero_price or 0.0))
    iaero_px = Decimal(str(iaero_price or 0.0))
    used_fallback = False
    if iaero_px <= 0 and aero_px > 0:
        # same fallback as the legacy keeper: iAERO ~= AERO (1:1); flagged, and sanity_problems() won't publish it
        iaero_px = aero_px
        used_fallback = True

    funded_usd = dex_usd = Decimal(0)
    unpriced: List[str] = []
    dex_priced: List[str] = []
    for f in funded:
        amt = int(f["amount"])
        if amt <= 0:
            continue
        px = Decimal(str(f.get("priceUsd") or 0.0))
        if px <= 0:
            unpriced.append(f["address"].lower())
            continue
        usd = Decimal(amt) / (Decimal(10) ** int(f.get("decimals", 18))) * px
        funded_usd += usd
        if f.get("source") == "dex":     # priced by PriceFetcher's on-chain fallback (see dex_guard_problem)
            dex_usd += usd
            dex_priced.append(f["address"].lower())

    staked_at_start = Decimal(int(staked_at_start_raw)) / E18
    staked_usd = staked_at_start * iaero_px
    weekly = (funded_usd / staked_usd) if staked_usd > 0 else Decimal(0)
    weekly_pct = float(weekly * 100)
    apy_pct = weekly_pct * WEEKS_PER_YEAR

    # legacy "estimated*" fields describe the gross harvest; the distributor receives the stakers' 80%
    gross = funded_usd * SPLIT_DENOM / SPLIT_BPS["stakers"]
    tvl_usd = Decimal(int(total_staked_raw)) / E18 * iaero_px
    ratio = (iaero_px / aero_px) if aero_px > 0 else Decimal(1)

    return {
        # ---- legacy fields (same names and units as EnhancedOptimizedVotesKeeper) ----
        "epochStart": int(epoch),
        "splitBps": dict(SPLIT_BPS),
        "protocolWeeklyUSD_1e18": _to_1e18(gross * SPLIT_BPS["protocol"] / SPLIT_DENOM),
        "pegWeeklyUSD_1e18": _to_1e18(gross * SPLIT_BPS["peg"] / SPLIT_DENOM),
        "estimatedWeeklyUSD_1e18": _to_1e18(gross),
        "estimatedWeeklyUSD_human": _human(gross),
        "stakersWeeklyUSD_1e18": _to_1e18(funded_usd),
        "stakersWeeklyUSD_human": _human(funded_usd),
        "estimatedAnnualUSD_1e18": _to_1e18(gross * WEEKS_PER_YEAR),
        "estimatedAnnualUSD_human": _human(gross * WEEKS_PER_YEAR),
        "totalStaked_1e18": str(int(total_staked_raw)),
        "tvlUSD_1e18": _to_1e18(tvl_usd),
        "apyPct": apy_pct,
        "aeroPrice_1e18": _to_1e18(aero_px),
        "iaeroPrice_1e18": _to_1e18(iaero_px),
        "iaeroAeroRatio_1e18": _to_1e18(ratio),
        "usedFallbackPrice": used_fallback,
        "updatedAt": datetime.fromtimestamp(now_ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "source": "ChainProcessingBot",
        # ---- new fields ----
        "method": "realized",
        "epoch": int(epoch),
        "epochEnd": int(epoch) + WEEK,
        "epochSelection": epoch_mode,
        "stale": bool(stale),
        "weeklyYieldPct": weekly_pct,
        "annualisation": "simple_x52",
        "priceBasis": "current",
        "distributor": (distributor or "").lower(),
        "fundedUSD_1e18": _to_1e18(funded_usd),
        "fundedUSD_human": _human(funded_usd),
        "stakedAtEpochStart_1e18": str(int(staked_at_start_raw)),
        "stakedUSD_1e18": _to_1e18(staked_usd),
        "stakedUSD_human": _human(staked_usd),
        "fundedTokenCount": sum(1 for f in funded if int(f["amount"]) > 0),
        "unpricedTokens": sorted(unpriced),
        "dexPricedTokens": sorted(dex_priced),
        "dexFundedUSD_1e18": _to_1e18(dex_usd),
        **({"staleReason": f"no funding newer than epoch {int(epoch)} for over 2 weeks"} if stale else {}),
    }


def build_estimated_rewards(
    w3,
    distributor: str,
    epochs_doc: dict,
    price_fetcher,
    decimals_fn: Callable[[List[str]], Dict[str, int]],
    now_ts: Optional[int] = None,
    epoch: Optional[int] = None,
    aero: str = AERO_ADDRESS,
    iaero: Optional[str] = None,
    epoch_mode: str = "latest_funded",
) -> dict:
    """
    Read funding for the selected epoch (see select_epoch) from the EpochStakingDistributor and price it.
    Token list per epoch comes from epochs.json (RewardFunded scan); amounts from rewardsForEpoch().
    """
    now_ts = int(now_ts if now_ts is not None else time.time())
    if epoch_mode not in EPOCH_MODES:
        logger.warning(f"[realized_yield] unknown epoch mode {epoch_mode!r}; using latest_funded")
        epoch_mode = "latest_funded"
    if epoch is not None:
        epoch, stale = int(epoch), False
    else:
        epoch, stale = select_epoch(epochs_doc, now_ts, epoch_mode)
    cs = w3.to_checksum_address
    dist = w3.eth.contract(cs(distributor), abi=DIST_ABI)

    ep = (epochs_doc.get("epochs") or {}).get(str(epoch)) or {}
    tokens = [] if stale else sorted({t.lower() for t in (ep.get("tokens") or []) if t})
    funded_raw: Dict[str, int] = {}
    for t in tokens:
        amt = int(dist.functions.rewardsForEpoch(cs(t), epoch).call())
        if amt > 0:
            funded_raw[t] = amt

    # same denominator the distributor pays out with (previewClaim)
    staked_at_start = int(dist.functions.supplySnapshotAtEpochStart(epoch).call())
    if staked_at_start == 0:
        staked_at_start = int(dist.functions.totalSupplyAtEpochStart(epoch).call())
    total_staked = int(dist.functions.totalStaked().call())
    if not iaero:
        try:
            iaero = dist.functions.iAERO().call()
        except Exception:
            iaero = IAERO_ADDRESS
    iaero, aero = iaero.lower(), aero.lower()

    # native ETH is funded as address(0): price it as WETH
    price_addr = {t: (WETH_ADDRESS if t == ZERO_ADDRESS else t) for t in funded_raw}
    want = sorted({a.lower() for a in price_addr.values()} | {aero, iaero})
    prices = price_fetcher.fetch_batch(want)
    px = lambda a: float((prices.get(a.lower()) or {}).get("priceUsd", 0.0))
    src = lambda a: (prices.get(a.lower()) or {}).get("source")

    erc20s = [t for t in funded_raw if t != ZERO_ADDRESS]
    decs = decimals_fn(erc20s) if erc20s else {}
    funded = [{
        "address": t,
        "amount": amt,
        "decimals": 18 if t == ZERO_ADDRESS else int(decs.get(t, 18)),
        "priceUsd": px(price_addr[t]),
        "source": src(price_addr[t]),
    } for t, amt in sorted(funded_raw.items())]

    out = compute_realized(
        epoch=epoch,
        funded=funded,
        staked_at_start_raw=staked_at_start,
        total_staked_raw=total_staked,
        iaero_price=px(iaero),
        aero_price=px(aero),
        distributor=distributor,
        now_ts=now_ts,
        epoch_mode=epoch_mode,
        stale=stale,
    )
    logger.info(
        f"[realized_yield] epoch={epoch} ({epoch_mode}{', STALE' if stale else ''}) tokens={out['fundedTokenCount']} "
        f"funded=${out['fundedUSD_human']} staked=${out['stakedUSD_human']} weekly={out['weeklyYieldPct']:.4f}% "
        f"apy={out['apyPct']:.2f}% unpriced={len(out['unpricedTokens'])}"
    )
    return out


# ---------------- data/yield_history.json ----------------
# Same schema as the rewards keeper's pushYieldHistoryToGitHub (ultimate-keeper.mjs):
#   {updatedAt, latest: {epoch, apyPct, tvlUSD_1e18, stakersWeeklyUSD_1e18},
#    series: [{epoch, timestamp, apyPct, tvlUSD_1e18, stakersWeeklyUSD_1e18}] sorted by epoch}
# Entry for epoch E = rewards funded INTO E (the keeper wrote it at E + ~1 min, right after funding).
# Our entries carry "method": "realized"; entries without it were published by the keeper and are never touched.

def yield_history_entry(payload: dict, now_ts: int) -> dict:
    return {
        "epoch": int(payload["epoch"]),
        "timestamp": int(now_ts),
        "apyPct": payload["apyPct"],
        "tvlUSD_1e18": payload["stakedUSD_1e18"],             # staked iAERO at epoch start x iAERO price
        "stakersWeeklyUSD_1e18": payload["fundedUSD_1e18"],   # realized funding to stakers for the epoch
        "method": "realized",
    }


def merge_yield_history(cur_doc: dict, payload: dict, now_ts: int) -> tuple:
    """
    Append or update ONLY the entry for payload["epoch"]. Returns (new_doc, reason); new_doc is None to skip.
    Never modifies any other entry, and never replaces an entry the keeper published (no "method").
    """
    series = cur_doc.get("series") if isinstance(cur_doc, dict) else None
    if not isinstance(series, list) or not series:
        return None, "existing yield_history.json missing/unreadable; refusing to start a new series"
    if payload.get("stale") or not payload.get("fundedTokenCount"):
        return None, f"epoch {payload.get('epoch')} has no current funding; no entry"
    entry = yield_history_entry(payload, now_ts)
    ep = entry["epoch"]
    idx = [i for i, x in enumerate(series) if int((x or {}).get("epoch", -1)) == ep]
    if idx:
        old = series[idx[0]]
        if old.get("method") != "realized":
            return None, f"epoch {ep} entry was published by the rewards keeper; not rewriting it"
        if all(old.get(k) == entry[k] for k in ("apyPct", "tvlUSD_1e18", "stakersWeeklyUSD_1e18")):
            return None, f"epoch {ep} entry unchanged"
        new_series = list(series)
        new_series[idx[0]] = entry
        reason = f"updated realized entry for epoch {ep}"
    else:
        if ep < max(int((x or {}).get("epoch", 0)) for x in series):
            return None, f"epoch {ep} is older than the newest entry; not inserting into history"
        new_series = sorted(list(series) + [entry], key=lambda x: int(x["epoch"]))
        reason = f"appended realized entry for epoch {ep}"
    latest = {k: entry[k] for k in ("epoch", "apyPct", "tvlUSD_1e18", "stakersWeeklyUSD_1e18", "method")}
    doc = {
        "updatedAt": datetime.fromtimestamp(int(now_ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "latest": latest,
        "series": new_series,
    }
    return doc, reason


def dump_yield_history(doc: dict) -> str:
    """Byte-compatible with the keeper's JSON.stringify(payload, null, 2) (insertion order, 2-space indent)."""
    return json.dumps(doc, indent=2)
