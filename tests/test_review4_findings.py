# test_review4_findings.py
# Fourth independent review of ChainProcessingBot PR #5 at acf45ac (rolling 7-day APY + trusted-DEX-token rule):
# R4_1 (M-1, the rolling window annualises lumps that pay for time before its anchor) and the flag-like
# ROLLING_SINCE_TS test. Every test asserts the SAFE behaviour and fails on acf45ac. No network: main's realized step
# runs end to end against an in-memory repo, a fake distributor and RewardFunded events with block times.
# Adapted (see comments): LUMP_TS is the on-chain block time; the harness has the 15 Oct Aerodrome week that is on
# chain (the last-completed fallback reads it); ROLLING_SINCE_TS before the cutoff (E0, 1) is now rejected.
# The review's R4_2, the rest of R4_3 and R4_4 are Lows and are not here.
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review4_findings.py
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import main  # noqa: E402
import realized_yield  # noqa: E402
from realized_yield import WEEK, epoch_start  # noqa: E402
from test_realized_yield import FakeDistributorWeb3, _keeper_history  # noqa: E402
from test_review2_findings import FakeRepo, FakeUpdater  # noqa: E402

E18 = 10 ** 18
DAY = 86400
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
WETH = "0x4200000000000000000000000000000000000006"
IAERO = "0x81034fb34009115f215f5d5f564aac9ffa46a1dc"
AERO = realized_yield.AERO_ADDRESS.lower()
LIQ = "0x7ee8964160126081cebc443a42482e95e393e6a8"     # any token other than AERO; only the address matters here

E_22_OCT = 1792627200            # Aero launch epoch ("E0"), Thu 22 Oct 00:00 UTC
LUMP_TS = 1792627305             # last Aerodrome-era weekly funding, booked into E_22_OCT (adapted: the block time,
                                 # 00:01:45, of block 52918979; the review used the keeper's 00:01:48 write time)
ALLOC = 1792635063               # #1584 first allocated (position_earnings.FIRST_ALLOCATION): Aero rewards accrue from here
RUN = 2 * 3600 + 31 * 60         # bot cron 02:31 UTC
HARVEST = 6 * 3600               # harvester runTimeUtc 06:00
STAKED_RAW = 4_710_927 * E18     # live staked iAERO
IAERO_PX = 0.6656
STAKED_USD = 4_710_927 * IAERO_PX
EP = "data/estimated_rewards_usd.json"
YH = "data/yield_history.json"
DAYS = ("Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed")


def weekly_usd(apy):
    return apy / 100 / 52 * STAKED_USD


def usdc_raw(usd):
    return round(usd * 10 ** 6)


class PF:
    """fetch_batch like PriceFetcher's: aggregator prices, or DEX prices with the pool's quote-side depth."""

    def __init__(self, llama, dex=None):
        self.llama, self.dex = llama, dex or {}

    def fetch_batch(self, addrs):
        out = {}
        for a in addrs:
            if a in self.llama:
                out[a] = {"priceUsd": self.llama[a], "source": "llama"}
            elif a in self.dex:
                px, depth = self.dex[a]
                out[a] = {"priceUsd": px, "source": "dex", "dexDepthUsd": depth}
            else:
                out[a] = {"priceUsd": 0.0, "source": "none"}
        return out


LLAMA = {USDC: 1.0, WETH: 2400.0, IAERO: IAERO_PX}
DEX_AERO = {AERO: (0.81, 6_100_000.0)}          # the Aero AERO/USDC pool 0xF634: trusted


def run_bot(repo, events, now, pf, env=None):
    """One 02:31 cron run of main._update_realized_yield. rewardsForEpoch / epochs.json are derived from `events`."""
    rewards, epochs = {}, {}
    for e in events:
        if e["timestamp"] < now:
            k = (e["token"], e["epoch"])
            rewards[k] = rewards.get(k, 0) + e["amount"]
            toks = epochs.setdefault(str(e["epoch"]), {"tokens": []})["tokens"]
            if e["token"] not in toks:
                toks.append(e["token"])
    repo.files["data/epochs.json"] = json.dumps({"epochs": epochs})
    w3 = FakeDistributorWeb3(rewards=rewards, snapshot={E_22_OCT + k * WEEK: STAKED_RAW for k in range(-4, 12)},
                             supply_at_start={}, total_staked=STAKED_RAW)
    scanner = mock.Mock(w3=w3)
    scanner.decimals_map.side_effect = lambda toks, **k: {USDC: 6}
    scanner.reward_funded_events.side_effect = lambda d, frm, to: [e for e in events if frm <= e["timestamp"] <= to]
    env_ = {"EPOCH_STAKING_DISTRIBUTOR": DIST, "LIVE_YIELD_ENABLED": "false", "YIELD_HISTORY_ENABLED": "true",
            "ROLLING_SINCE_TS": "", "TRUSTED_DEX_TOKENS": ""}
    env_.update(env or {})
    with mock.patch.dict(os.environ, env_), mock.patch("time.time", return_value=now):
        main._update_realized_yield(repo, FakeUpdater(repo), scanner, pf)
    return json.loads(repo.files[EP])


def lump_event():
    """The real 22 Oct 00:01:45 funding: one Aerodrome week ($9,063 at today's prices, 15.03%), shown as USDC.
    Adapted: also the 15 Oct one, as on chain (the keeper funded every Thursday), at the same rate."""
    return [{"token": USDC, "epoch": ep, "amount": usdc_raw(weekly_usd(15.0)), "timestamp": ep + 105, "blockNumber": 1}
            for ep in (E_22_OCT - WEEK, E_22_OCT)]


def aero_harvests(first_run, until, apy, accrual_start=ALLOC):
    """The Aero-era harvester: every day at 06:00 from `first_run` it funds the CURRENT epoch with everything #1584
    accrued since the previous harvest (rewards stream continuously; the first run claims all of it since the stake's
    first allocation). Steady rate `apy`."""
    per_sec = weekly_usd(apy) / WEEK
    out, prev, ts = [], accrual_start, first_run
    while ts < until:
        out.append({"token": USDC, "epoch": epoch_start(ts), "amount": usdc_raw(per_sec * (ts - prev)),
                    "timestamp": ts, "blockNumber": ts // 2})
        prev, ts = ts, ts + DAY
    return out


def fresh_repo():
    return FakeRepo({EP: json.dumps({"apyPct": 19.2, "updatedAt": "2026-10-21T22:51:31.937Z"}),
                     YH: json.dumps(_keeper_history())})


def week_of_runs(since, first_run, apy=15.0, start=E_22_OCT + DAY, days=8, lump=True):
    """Daily 02:31 runs from Fri 23 Oct; returns [(day, apyPct, apyWindow spanDays)]."""
    repo, got = fresh_repo(), []
    until = start + days * DAY + RUN
    events = (lump_event() if lump else []) + aero_harvests(first_run, until, apy)
    for d in range(days):
        now = start + d * DAY + RUN
        out = run_bot(repo, events, now, PF(LLAMA, DEX_AERO), env={"ROLLING_SINCE_TS": str(since)})
        got.append((DAYS[(now - E_22_OCT) // DAY % 7] + time_label(now), round(out["apyPct"], 2),
                    (out.get("apyWindow") or {}).get("spanDays")))
    return got


def time_label(ts):
    return f" {(ts - E_22_OCT) // DAY + 22} Oct" if ts < E_22_OCT + 10 * DAY else f" {(ts - E_22_OCT) // DAY - 9} Nov"


# ------------------------------------------------------------------------------------------------------------------
class R4_1_RollingAnchorAnnualisesLumps(unittest.TestCase):
    """M-1. The rolling window [max(now-7d, ROLLING_SINCE_TS), now) annualises whatever was funded inside it over its
    span. While the window is clamped by ROLLING_SINCE_TS (the first 7 days), any funding that pays for accrual from
    BEFORE the anchor is annualised over a 1-7 day span. The true rate in every scenario below is a steady 15% (before
    and after the migration), so every published figure should be within 15% +-25% (R3_1's band)."""

    BAND = (11.25, 18.75)

    def _bad(self, got):
        return [g for g in got if not self.BAND[0] <= g[1] <= self.BAND[1]]

    def test_anchor_at_the_aero_launch_epoch_annualises_the_last_aerodrome_week(self):
        # ROLLING_SINCE_TS=1792627200 (E0 = "Aero era start", the runbook's key date): the 22 Oct 00:01:45 funding
        # (one whole Aerodrome week) sits inside the window and is annualised over 1.1 .. 6.1 days.
        # Adapted: E0 is before the cutoff (just after that funding), so it is rejected with an error and the bot stays
        # in the per-epoch mode; the review asserted the 15% band, which only a clamped anchor would give.
        with self.assertLogs("main", "ERROR") as logs:
            got = week_of_runs(since=E_22_OCT, first_run=E_22_OCT + DAY + HARVEST)    # harvester from Fri 23 Oct 06:00
        self.assertEqual([g for g in got if g[2] is not None], [], f"rolling windows over the Aerodrome week: {got}")
        self.assertTrue(any("ROLLING_SINCE_TS" in m and "rejected" in m for m in logs.output))

    def test_documented_anchor_annualises_the_first_runs_catch_up(self):
        # ROLLING_SINCE_TS = the harvester's first run (the commit message / docstring). That run claims everything
        # #1584 accrued since its first allocation (22 Oct 02:11:03); here it starts Sat 24 Oct 06:00 (2.16 days of
        # accrual), and the per-epoch fallback of the first day also adds it to the Aerodrome week.
        t0 = E_22_OCT + 2 * DAY + HARVEST
        got = week_of_runs(since=t0, first_run=t0)
        self.assertFalse(self._bad(got), f"true rate 15%; published (day, apyPct, spanDays): {got}")

    def test_anchor_set_before_the_first_funding_publishes_zero(self):
        # ROLLING_SINCE_TS set to the PLANNED first run (Fri 23 Oct 06:00) and the launch slips two days (base
        # forwarder still null in config/mainnet.json; the keeper has several "nothing distributed" paths): once the
        # window spans a day with no RewardFunded event, apyPct 0 passes sanity_problems() and is published.
        got = week_of_runs(since=E_22_OCT + DAY + HARVEST, first_run=E_22_OCT + 3 * DAY + HARVEST)
        zeros = [g for g in got if g[1] == 0]
        self.assertFalse(zeros, f"#1584 is earning 15% throughout; published (day, apyPct, spanDays): {got}")


# ------------------------------------------------------------------------------------------------------------------
class R4_3_EnvParsingFootguns(unittest.TestCase):
    """L-2 (only the flag-like ROLLING_SINCE_TS test is adopted)."""

    def test_flag_like_rolling_since_does_not_count_the_aerodrome_week_twice(self):
        # ROLLING_SINCE_TS=1 ("on") is accepted: a full 7-day window from day one, holding the Aerodrome week paid on
        # 22 Oct 00:01:45 AND the Aero harvests (+ catch-up) for the same days.
        # Adapted: 1 (and 0, negative) is rejected with an error -> per-epoch mode; no rolling window holds both
        for flag in (1, 0, -1):
            with self.assertLogs("main", "ERROR") as logs:
                got = week_of_runs(since=flag, first_run=E_22_OCT + DAY + HARVEST)
            self.assertEqual([g for g in got if g[2] is not None], [], f"ROLLING_SINCE_TS={flag}: {got}")
            self.assertTrue(any("rejected" in m for m in logs.output))


if __name__ == "__main__":
    unittest.main()
