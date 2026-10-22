# test_review5_findings.py
# Fifth independent review of ChainProcessingBot PR #5 at b7bb436 (catch-up anchors, cutoff clamp, fallback).
# Every test asserts the SAFE behaviour and FAILS on b7bb436. No network: main._update_realized_yield runs end to end
# against the repo's own R4 harness (in-memory repo, fake distributor, RewardFunded events with block times).
# The true rate in every scenario is a steady 15% (#1584 accrues continuously from its first allocation, 22 Oct
# 02:11:03; the Aerodrome weeks of 15 and 22 Oct are funded at the same rate), so a published figure outside
# 15% +-25% (R3_1 / R4_1's band, 11.25 .. 18.75) is wrong.
# Adopted: R5_1 (M-1), R5_2 (L-1), R5_3 (L-2), unchanged except the import paths; R5_4 / R5_5 (Lows / Info) are
# not here. ROLLING_SINCE_TS, which the scenarios still set, is now ignored (the rolling rate is automatic).
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review5_findings.py
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import main  # noqa: E402
import test_review4_findings as T  # noqa: E402  (the repo's adapted R4 harness: run_bot, PF, lump_event, ...)

DAY, H = T.DAY, 3600
BAND = (11.25, 18.75)
PER_SEC = T.weekly_usd(15.0) / T.WEEK          # USD per second accrued by #1584 for the stakers at a true 15%
# Leaf-chain share of #1584's earnings: the harvester README's first-run sizing (Ethereum ~$500/d, Robinhood ~$250/d)
# against Base ~$3,500/d (the dry run's live block measured Base $3,498/d, Ethereum $421/d; chain 4663 unmeasured).
LEAF = 750 / 4250
THU_29 = T.E_22_OCT + 7 * DAY + T.HARVEST      # first live run Thu 29 Oct 06:00 (launch date is open)
MON_26 = T.E_22_OCT + 4 * DAY + T.HARVEST


def ev(ts, usd):
    return {"token": T.USDC, "epoch": T.epoch_start(ts), "amount": T.usdc_raw(usd), "timestamp": ts,
            "blockNumber": ts // 2}


def daily_runs(events, first_now, days, env=None):
    """Daily 02:31 runs; returns [(label, apyPct, spanDays or 'fallback')]."""
    repo, got = T.fresh_repo(), []
    env = dict({"ROLLING_SINCE_TS": "1"}, **(env or {}))
    for k in range(days):
        now = first_now + k * DAY
        out = T.run_bot(repo, T.lump_event() + events, now, T.PF(T.LLAMA, T.DEX_AERO), env=env)
        got.append((T.DAYS[(now - T.E_22_OCT) // DAY % 7] + T.time_label(now), round(out["apyPct"], 2),
                    "fallback" if out.get("rollingFallback") else (out.get("apyWindow") or {}).get("spanDays")))
    return got, repo


def bad(got):
    return [g for g in got if not BAND[0] <= g[1] <= BAND[1]]


def harvests(t0, until, base_prev=T.ALLOC, leaf_prev=T.ALLOC, first=None):
    """Daily 06:00 harvests from t0; each funds what accrued since that part's previous harvest. `first(t)` may
    replace the first day's events (returns (events, base_prev, leaf_prev))."""
    out, ts = [], t0
    if first:
        evs, base_prev, leaf_prev = first(ts)
        out += evs
        ts += DAY
    while ts < until:
        out.append(ev(ts, PER_SEC * ((1 - LEAF) * (ts - base_prev) + LEAF * (ts - leaf_prev))))
        base_prev = leaf_prev = ts
        ts += DAY
    return out


# ----------------------------------------------------------------------------------------------------------------
class R5_1_PartialFirstFundingBecomesTheCatchUpAnchor(unittest.TestCase):
    """M-1. funding_anchors() treats the FIRST RewardFunded at/after ROLLING_SINCE_TS (raised to the cutoff) as the
    whole catch-up and drops it; rolling_bounds() then annualises everything after it over (T_last - T0). When the
    first Aero-era funding is only PART of the catch-up, the rest of the catch-up (up to 7 days of accrual) is
    annualised over ~1-2 days. Each scenario is a documented harvester path."""

    def test_leaf_only_first_distribution_after_a_failed_base_harvest(self):
        # keeper run.ts: "Distribution needs no claim: it runs even when the harvest failed ... so Rift USDC already in
        # the harvester always reaches the stakers". First live run: Base forwarder.harvest throws (new code, first
        # run), the leaf catch-up's Rift USDC is distributed alone (~07:15, after the order wait); the Base catch-up
        # (8.16 days of accrual) is distributed by the next day's run.
        def first(t):
            return [ev(t + 75 * 60, PER_SEC * LEAF * (t - T.ALLOC))], T.ALLOC, t
        events = harvests(THU_29, THU_29 + 12 * DAY, first=first)
        got, _ = daily_runs(events, THU_29 - T.HARVEST + DAY + T.RUN, 9)
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")

    def test_owner_test_distribution_before_the_first_keeper_run(self):
        # a $50 processAndDistribute (owner/keeper smoke test of the 80/10/10 path, e.g. with the README's hand-paid
        # Rift test-order USDC sitting in the harvester) 18 h before the first keeper run: it becomes the anchor and
        # the real catch-up is counted
        events = [ev(THU_29 - 18 * H, 50.0)] + harvests(THU_29, THU_29 + 12 * DAY)
        got, _ = daily_runs(events, THU_29 - T.HARVEST + DAY + T.RUN, 9)
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")

    def test_supervised_base_first_launch_counts_the_leaf_catch_up(self):
        # README "First live run": "optionally one chain at a time with KEEPER_CHAINS": Base alone first, the leaf
        # chains from the next day's run
        def first(t):
            return [ev(t, PER_SEC * (1 - LEAF) * (t - T.ALLOC))], t, T.ALLOC
        events = harvests(THU_29, THU_29 + 12 * DAY, first=first)
        got, _ = daily_runs(events, THU_29 - T.HARVEST + DAY + T.RUN, 9)
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")

    def test_rift_delivery_after_the_order_wait_counts_the_leaf_catch_up(self):
        # orders.ts: orders still open after orderWaitMinutes (75) are "resumed next run": the leaf catch-up's USDC is
        # distributed with the next day's run (and every day's leaf part lags one day)
        out, base_prev, leaf_prev, pending, ts = [], T.ALLOC, T.ALLOC, 0.0, THU_29
        while ts < THU_29 + 12 * DAY:
            out.append(ev(ts, PER_SEC * (1 - LEAF) * (ts - base_prev) + pending))
            pending, base_prev, leaf_prev = PER_SEC * LEAF * (ts - leaf_prev), ts, ts
            ts += DAY
        got, _ = daily_runs(out, THU_29 - T.HARVEST + DAY + T.RUN, 9)
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")


# ----------------------------------------------------------------------------------------------------------------
class R5_2_ShortOutageCatchUpIsAnnualised(unittest.TestCase):
    """L-1. Only a funding after >= 7 days without one is a catch-up. After a shorter outage (Base gas above
    maxGasPriceGwei skips harvest AND distribution; a run that throws waits for the next day) the catch-up lump sits
    in the plain [now - 7 d, now) window with up to 6 later fundings: up to (gap + 6) / 7 of the true rate, and a
    cliff at exactly 7 days."""

    def _outage(self, gap):
        first = T.E_22_OCT + DAY + T.HARVEST
        last_before = first + 13 * DAY               # Thu 5 Nov 06:00
        times = [first + k * DAY for k in range(14)] + [last_before + gap + k * DAY for k in range(15)]
        events, prev = [], T.ALLOC
        for t in times:
            events.append(ev(t, PER_SEC * (t - prev)))
            prev = t
        got, _ = daily_runs(events, last_before - T.HARVEST + DAY + T.RUN, 16)
        return got

    def test_six_day_outage_then_catch_up(self):
        got = self._outage(6 * DAY)
        over = [g for g in got if g[1] > BAND[1]]
        self.assertFalse(over, f"6-day outage, true 15%; published (day, apyPct, spanDays): {got}")

    def test_gap_one_minute_under_seven_days(self):
        got = self._outage(7 * DAY - 60)
        over = [g for g in got if g[1] > BAND[1]]
        self.assertFalse(over, f"outage of 7 d - 60 s (7 d exactly publishes 15.0%); published: {got}")


# ----------------------------------------------------------------------------------------------------------------
class R5_3_FallbackDoubleCountsTheTransitionEpoch(unittest.TestCase):
    """L-2. The fallback publishes rewardsForEpoch(last completed epoch) less only the anchor fundings. From Thu 29 Oct
    to Wed 4 Nov that epoch is 1792627200, which holds the Aerodrome week paid at 00:01:45 (for 15-22 Oct) AND any
    Aero-era funding for 22-29 Oct that is not an anchor: both are published as one week."""

    def test_rolling_since_set_after_the_harvester_started(self):
        # harvester live from Fri 23 Oct 06:00; ROLLING_SINCE_TS set on Thu 29 Oct 12:00 (switching away from the
        # per-epoch partial week): Fri 30 and Sat 31 publish the fallback for epoch 1792627200
        events = harvests(T.E_22_OCT + DAY + T.HARVEST, T.E_22_OCT + 12 * DAY)
        since = T.E_22_OCT + 7 * DAY + 12 * H
        got, _ = daily_runs(events, T.E_22_OCT + 8 * DAY + T.RUN, 3, env={"ROLLING_SINCE_TS": str(since)})
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")

    def test_test_distribution_then_catch_up_inside_the_transition_epoch(self):
        # R5_1's smoke test on Tue 27 12:00, first keeper run Wed 28 06:00: Thu 29's fallback = Aerodrome week +
        # 6.16-day catch-up - $50
        t0 = T.E_22_OCT + 6 * DAY + T.HARVEST
        events = [ev(t0 - 18 * H, 50.0)] + harvests(t0, t0 + 10 * DAY)
        got, _ = daily_runs(events, t0 - T.HARVEST + DAY + T.RUN, 1)
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays): {got}")


if __name__ == "__main__":
    unittest.main()
