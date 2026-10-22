# realized_yield.py
"""
Realized staking yield for data/estimated_rewards_usd.json and data/yield_history.json
(replaces the legacy EnhancedOptimizedVotesKeeper estimate and the rewards keeper's yield snapshot).

Funding: the EpochStakingDistributor receives the stakers' 80% of each harvest and books it to an epoch (weeks start
Thursday 00:00 UTC, E = ts // WEEK * WEEK), emitting RewardFunded(token, epochId, amount). Until 22 Oct 2026 the
rewards keeper funded once a week (Thursday 00:01, into the new epoch). The Aero-era harvester funds every day (06:00
UTC) into the RUNNING epoch, so a running epoch only holds part of a week.

Headline figures (estimated_rewards_usd.json), in one of two modes:
  rolling        (env ROLLING_SINCE_TS set, unix seconds: the daily harvester's first run)
                 window = [max(now - 7 d, ROLLING_SINCE_TS), now), used once it spans >= 1 day (before that: per-epoch)
                 fundedUSD        = RewardFunded amounts with block time in the window * current USD price
                 stakersWeeklyUSD = fundedUSD * 7 / spanDays; apyWindow = {from, to, spanDays}
  per-epoch      (ROLLING_SINCE_TS unset) epoch E chosen by ESTIMATED_REWARDS_EPOCH:
                 latest_funded  (default) newest epoch with funding in epochs.json; older than 2 weeks -> 0 (stale)
                 last_completed the most recent epoch whose week has ended
                 fundedUSD = stakersWeeklyUSD = sum over tokens of rewardsForEpoch(token, E) * current USD price
  stakedUSD      = staked iAERO at the epoch's start (the distributor's payout denominator) * iAERO price
  weeklyYieldPct = stakersWeeklyUSD / stakedUSD * 100
  apyPct         = weeklyYieldPct * 52            (simple annualisation, no compounding)

Prices are CURRENT prices from PriceFetcher, not prices at funding time. A token priced by PriceFetcher's on-chain DEX
fallback counts only when trusted: listed in TRUSTED_DEX_TOKENS (env, comma-separated; default the Aero AERO) and
priced from a pool holding >= DEX_TRUSTED_DEPTH_USD on its quote side. Other DEX-priced tokens are left out of the
figures and listed in excludedTokens. Not published (main.py logs and keeps the previous file) when sanity_problems()
finds anything (apyPct NaN, negative or > 500%; AERO or iAERO unpriced; a zero USD stake).

yield_history.json: one entry per COMPLETED epoch with the same rules (rolling mode: the RewardFunded events inside
the epoch and >= ROLLING_SINCE_TS, annualised over that part; no entry if it is under a day). Keeper-written entries
are never touched.
Readers of estimated_rewards_usd.json: TwitterBot (apyPct), DefiLlama yield-server iaero-protocol
(apyPct, tvlUSD_1e18), iaero-frontend (stakersWeeklyUSD_1e18, estimatedWeeklyUSD_1e18).
All legacy fields are kept with the same names and units; new fields are only added.
"""
import json
import math
import os
import time
import logging
from datetime import datetime, timezone
from decimal import Decimal, getcontext
from typing import Callable, Dict, Iterable, List, Optional

getcontext().prec = 60

logger = logging.getLogger(__name__)

DAY = 24 * 60 * 60
WEEK = 7 * DAY
WEEKS_PER_YEAR = 52
E18 = 10 ** 18
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
WETH_ADDRESS = "0x4200000000000000000000000000000000000006"
AERO_ADDRESS = "0x3f5bF3EdAc59d650D8fDf9657a71F2f904A3a4Ee"   # Aero AERO (post-migration)
IAERO_ADDRESS = "0x81034Fb34009115F215f5d5F564AAc9FfA46a1Dc"

EPOCH_MODES = ("latest_funded", "last_completed")
STALE_AFTER_SEC = 2 * WEEK      # latest funded epoch older than this -> publish 0, not a stale figure
MAX_SANE_APY_PCT = 500.0        # above this, don't publish (likely a bad price), log and skip
TRUSTED_DEX_TOKENS = (AERO_ADDRESS.lower(),)   # DEX prices that may count (env TRUSTED_DEX_TOKENS, comma-separated)
DEX_TRUSTED_DEPTH_USD = 1_000_000.0            # ... when their pool's quote side is this deep (env DEX_TRUSTED_DEPTH_USD)
MIN_WINDOW_DAYS = 1.0           # a funding window shorter than this is not annualised

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


def trusted_dex_tokens() -> set:
    """Tokens whose DEX price may count (env TRUSTED_DEX_TOKENS, comma-separated; blank or unset -> the Aero AERO)."""
    toks = {t.strip().lower() for t in (os.environ.get("TRUSTED_DEX_TOKENS") or "").split(",") if t.strip()}
    return toks or set(TRUSTED_DEX_TOKENS)


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
    dex_trusted_depth_usd: Optional[float] = None,
    trusted_tokens: Optional[Iterable[str]] = None,
    span_days: float = 7.0,
) -> dict:
    """
    Pure computation of the estimated_rewards_usd.json payload.
    funded: [{"address", "amount" (raw int), "decimals", "priceUsd", optional "source" and "dexDepthUsd"}]: the
    funding of `epoch`, or of a window of `span_days` days (stakersWeeklyUSD = fundedUSD * 7 / span_days).
    stale=True publishes 0 for `epoch` (its funding is too old to be a current yield).
    A "dex"-sourced price counts only if the token is in trusted_tokens (default trusted_dex_tokens()) and its pool
    depth is >= dex_trusted_depth_usd (default env DEX_TRUSTED_DEPTH_USD, else DEX_TRUSTED_DEPTH_USD); other
    DEX-priced tokens are left out and listed in excludedTokens.
    """
    if dex_trusted_depth_usd is None:
        dex_trusted_depth_usd = float(os.environ.get("DEX_TRUSTED_DEPTH_USD") or DEX_TRUSTED_DEPTH_USD)
    trusted_tokens = {t.lower() for t in (trusted_tokens if trusted_tokens is not None else trusted_dex_tokens())}
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

    funded_usd = Decimal(0)
    unpriced: List[str] = []
    dex_priced: List[dict] = []
    excluded: List[dict] = []
    for f in funded:
        amt = int(f["amount"])
        if amt <= 0:
            continue
        px = Decimal(str(f.get("priceUsd") or 0.0))
        if px <= 0:
            unpriced.append(f["address"].lower())
            continue
        usd = Decimal(amt) / (Decimal(10) ** int(f.get("decimals", 18))) * px
        if f.get("source") == "dex":     # priced by PriceFetcher's on-chain fallback
            depth = f.get("dexDepthUsd")
            trusted = (f["address"].lower() in trusted_tokens and isinstance(depth, (int, float))
                       and depth >= dex_trusted_depth_usd)
            dex_priced.append({"address": f["address"].lower(), "fundedUSD": round(float(usd), 4),
                               "poolDepthUsd": depth, "trusted": trusted})
            if not trusted:
                excluded.append({"address": f["address"].lower(), "fundedUSD": round(float(usd), 4),
                                 "poolDepthUsd": depth, "reason": "untrusted DEX price"})
                continue
        funded_usd += usd

    weekly_usd = funded_usd * 7 / Decimal(str(span_days)) if span_days and span_days > 0 else funded_usd
    staked_at_start = Decimal(int(staked_at_start_raw)) / E18
    staked_usd = staked_at_start * iaero_px
    weekly = (weekly_usd / staked_usd) if staked_usd > 0 else Decimal(0)
    weekly_pct = float(weekly * 100)
    apy_pct = weekly_pct * WEEKS_PER_YEAR

    # legacy "estimated*" fields describe the gross harvest; the distributor receives the stakers' 80%
    gross = weekly_usd * SPLIT_DENOM / SPLIT_BPS["stakers"]
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
        "stakersWeeklyUSD_1e18": _to_1e18(weekly_usd),
        "stakersWeeklyUSD_human": _human(weekly_usd),
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
        "dexPricedTokens": sorted(dex_priced, key=lambda x: x["address"]),
        "excludedTokens": sorted(excluded, key=lambda x: x["address"]),
        **({"staleReason": f"no funding newer than epoch {int(epoch)} for over 2 weeks"} if stale else {}),
    }


def _price_and_compute(w3, distributor: str, funded_raw: Dict[str, int], epoch: int, price_fetcher,
                       decimals_fn: Callable[[List[str]], Dict[str, int]], aero: str, iaero: Optional[str],
                       now_ts: int, epoch_mode: str, stale: bool, span_days: float) -> dict:
    """Price `funded_raw` {token: raw amount} and compute the payload against the stake at `epoch`'s start."""
    cs = w3.to_checksum_address
    dist = w3.eth.contract(cs(distributor), abi=DIST_ABI)
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
    depth = lambda a: (prices.get(a.lower()) or {}).get("dexDepthUsd")

    erc20s = [t for t in funded_raw if t != ZERO_ADDRESS]
    decs = decimals_fn(erc20s) if erc20s else {}
    funded = [{
        "address": t,
        "amount": amt,
        "decimals": 18 if t == ZERO_ADDRESS else int(decs.get(t, 18)),
        "priceUsd": px(price_addr[t]),
        "source": src(price_addr[t]),
        "dexDepthUsd": depth(price_addr[t]),
    } for t, amt in sorted(funded_raw.items())]

    return compute_realized(
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
        span_days=span_days,
    )


def _log_payload(out: dict, label: str) -> None:
    logger.info(
        f"[realized_yield] {label} tokens={out['fundedTokenCount']} funded=${out['fundedUSD_human']} "
        f"weekly=${out['stakersWeeklyUSD_human']} staked=${out['stakedUSD_human']} weekly={out['weeklyYieldPct']:.4f}% "
        f"apy={out['apyPct']:.2f}% unpriced={len(out['unpricedTokens'])} excluded={len(out['excludedTokens'])}"
    )


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
    Per-epoch mode: read funding for the selected epoch (see select_epoch) from the EpochStakingDistributor and price it.
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

    out = _price_and_compute(w3, distributor, funded_raw, epoch, price_fetcher, decimals_fn, aero, iaero, now_ts,
                             epoch_mode, stale, 7.0)
    _log_payload(out, f"epoch={epoch} ({epoch_mode}{', STALE' if stale else ''})")
    return out


def build_window_rewards(
    w3,
    distributor: str,
    events: Iterable[dict],
    window_from: int,
    window_to: int,
    price_fetcher,
    decimals_fn: Callable[[List[str]], Dict[str, int]],
    stake_epoch: int,
    now_ts: Optional[int] = None,
    aero: str = AERO_ADDRESS,
    iaero: Optional[str] = None,
    label: str = "rolling_7d",
) -> dict:
    """
    Funding booked in a time window: RewardFunded events {token, amount, timestamp} with window_from <= block time
    < window_to, whatever epoch they were booked to, annualised over the window (stakersWeeklyUSD = funded * 7 /
    spanDays). The stake denominator is the one at `stake_epoch`'s start. Adds apyWindow {from, to, spanDays}.
    """
    now_ts = int(now_ts if now_ts is not None else time.time())
    span_days = (int(window_to) - int(window_from)) / DAY
    funded_raw: Dict[str, int] = {}
    for e in events or []:
        if int(window_from) <= int(e["timestamp"]) < int(window_to) and int(e["amount"]) > 0:
            t = str(e["token"]).lower()
            funded_raw[t] = funded_raw.get(t, 0) + int(e["amount"])
    out = _price_and_compute(w3, distributor, funded_raw, int(stake_epoch), price_fetcher, decimals_fn, aero, iaero,
                             now_ts, label, False, span_days)
    out["apyWindow"] = {"from": int(window_from), "to": int(window_to), "spanDays": round(span_days, 6)}
    _log_payload(out, f"window {int(window_from)}..{int(window_to)} ({span_days:.3f} d, {label})")
    return out


# ---------------- data/yield_history.json ----------------
# Same schema as the rewards keeper's pushYieldHistoryToGitHub (ultimate-keeper.mjs):
#   {updatedAt, latest: {epoch, apyPct, tvlUSD_1e18, stakersWeeklyUSD_1e18},
#    series: [{epoch, timestamp, apyPct, tvlUSD_1e18, stakersWeeklyUSD_1e18}] sorted by epoch}
# Entry for epoch E = rewards funded INTO E (the keeper wrote it at E + ~1 min, right after funding); ours are written
# once E has ended (main.py), from rewardsForEpoch or, in rolling mode, from the RewardFunded events inside E.
# Our entries carry "method": "realized"; entries without it were published by the keeper and are never touched.

def yield_history_entry(payload: dict, now_ts: int) -> dict:
    return {
        "epoch": int(payload["epoch"]),
        "timestamp": int(now_ts),
        "apyPct": payload["apyPct"],
        "tvlUSD_1e18": payload["stakedUSD_1e18"],             # staked iAERO at epoch start x iAERO price
        # realized funding to stakers for the epoch (per week: rolling mode may cover part of the epoch)
        "stakersWeeklyUSD_1e18": payload.get("stakersWeeklyUSD_1e18", payload["fundedUSD_1e18"]),
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
