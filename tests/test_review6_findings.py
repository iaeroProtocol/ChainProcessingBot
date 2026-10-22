# test_review6_findings.py
# Sixth independent review of ChainProcessingBot PR #5 at cae9b99 (accrual-based rolling APY, automatic from the
# first Aero-era funding). Every test asserts the SAFE behaviour and FAILS on cae9b99. No network:
# main._update_realized_yield runs end to end against the repo's own R4 harness (in-memory repo, fake distributor,
# RewardFunded events with block times). True rate: a steady 15% (#1584 accrues continuously from 22 Oct 02:11:03;
# each funding pays for the accrual since the previous one), so a figure outside 15% +-25% (11.25 .. 18.75) is wrong.
# Adopted: R6_1 (M-1) and R6_2 (M-2); R6_3 / R6_4 (Lows) are not here. Only the import paths differ, except
# R6_2's first test (see its comment).
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review6_findings.py
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import main  # noqa: E402
import test_review4_findings as T  # noqa: E402  (run_bot's world: PF, LLAMA, lump_event, fresh_repo, ...)
from test_realized_yield import FakeDistributorWeb3  # noqa: E402
from test_review2_findings import FakeUpdater  # noqa: E402

DAY, H = T.DAY, 3600
BAND = (11.25, 18.75)
PER_SEC = T.weekly_usd(15.0) / T.WEEK
E0 = T.E_22_OCT


def at(day_offset, hour=6, minute=0):
    """Block time `day_offset` days after Thu 22 Oct 00:00 UTC at hh:mm."""
    return E0 + day_offset * DAY + hour * H + minute * 60


def run_at(day_offset):
    return at(day_offset, 2, 31)                      # the bot's 02:31 cron


def label(ts):
    return T.DAYS[(ts - E0) // DAY % 7] + T.time_label(ts)


def accrual_events(times, start=T.ALLOC, usd_per_sec=PER_SEC):
    """Each funding pays for #1584's accrual since the previous one (the first: since its first allocation)."""
    out, prev = [], start
    for t in sorted(times):
        out.append({"token": T.USDC, "epoch": T.epoch_start(t), "amount": T.usdc_raw(usd_per_sec * (t - prev)),
                    "timestamp": t, "blockNumber": t // 2})
        prev = t
    return out


def run_bot(repo, events, now, env=None, fail=None):
    """T.run_bot with an optional fail(frm_ts, to_ts, now) -> bool: the RPC refuses that RewardFunded scan."""
    rewards, epochs = {}, {}
    for e in events:
        if e["timestamp"] < now:
            k = (e["token"], e["epoch"])
            rewards[k] = rewards.get(k, 0) + e["amount"]
            toks = epochs.setdefault(str(e["epoch"]), {"tokens": []})["tokens"]
            if e["token"] not in toks:
                toks.append(e["token"])
    repo.files["data/epochs.json"] = json.dumps({"epochs": epochs})
    w3 = FakeDistributorWeb3(rewards=rewards, snapshot={E0 + k * T.WEEK: T.STAKED_RAW for k in range(-4, 16)},
                             supply_at_start={}, total_staked=T.STAKED_RAW)
    scanner = mock.Mock(w3=w3)
    scanner.decimals_map.side_effect = lambda toks, **k: {T.USDC: 6}

    def scan(d, frm, to):
        if fail and fail(frm, to, now):
            raise Exception("429 Client Error: Too Many Requests")
        return [e for e in events if frm <= e["timestamp"] <= to]
    scanner.reward_funded_events.side_effect = scan
    env_ = {"EPOCH_STAKING_DISTRIBUTOR": T.DIST, "LIVE_YIELD_ENABLED": "false", "YIELD_HISTORY_ENABLED": "true",
            "ROLLING_SINCE_TS": "", "TRUSTED_DEX_TOKENS": "", "ROLLING_CUTOFF_TS": "",
            "PROTOCOL_AERO_STAKE_SINCE": "", "PROTOCOL_AERO_STAKE_ID": ""}
    env_.update(env or {})
    with mock.patch.dict(os.environ, env_), mock.patch("time.time", return_value=now):
        main._update_realized_yield(repo, FakeUpdater(repo), scanner, T.PF(T.LLAMA, T.DEX_AERO))
    return json.loads(repo.files[T.EP])


def daily(events, first_now, days, env=None, fail=None, repo=None):
    """Daily 02:31 runs; [(label, apyPct, spanDays | 'fallback' | 'per-epoch', updatedAt)]."""
    repo, got = repo or T.fresh_repo(), []
    for k in range(days):
        now = first_now + k * DAY
        o = run_bot(repo, T.lump_event() + events, now, env=env, fail=fail)
        mode = ("fallback" if o.get("rollingFallback") else (o.get("apyWindow") or {}).get("spanDays")
                if o.get("apyWindow") else "per-epoch")
        got.append((label(now), round(o["apyPct"], 2), mode, o.get("updatedAt")))
    return got, repo


def bad(got):
    return [g[:3] for g in got if not BAND[0] <= g[1] <= BAND[1]]


# ------------------------------------------------------------------------------------------------------------------
class R6_1_FallbackPublishesACatchUpAsOneWeek(unittest.TestCase):
    """rolling_plan() needs a funding at or before now - 7 d IN VIEW, and the scan starts at hist_epoch - 7 d
    (main.py:417). After an outage that leaves a whole epoch unfunded, the last pre-outage funding falls out of view, so
    the plan is None and the fallback publishes rewardsForEpoch(last completed epoch) "as is" (purely Aero-era,
    realized_yield.py:423-427). That epoch holds the catch-up, which pays for the whole outage: it is published as ONE
    week."""

    def test_two_week_outage_then_catch_up(self):
        # daily 06:00 from Fri 23 Oct; nothing from Thu 5 Nov to Tue 17 Nov (e.g. the Railway service down, the
        # harvester or distributor paused during an incident); the Wed 18 Nov run funds the 14 days; daily after
        times = [at(d) for d in range(1, 14)] + [at(d) for d in range(27, 40)]
        got, _ = daily(accrual_events(times), run_at(28), 8)          # Thu 19 .. Thu 26 Nov
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in got]}")

    def test_eight_day_outage_covering_one_epoch(self):
        # the last funding Wed 11 Nov 06:00, the next Thu 19 Nov 06:00 (8 days): epoch 12-19 Nov has none
        times = [at(d) for d in range(1, 21)] + [at(d) for d in range(28, 40)]
        got, _ = daily(accrual_events(times), run_at(29), 8)          # Fri 20 .. Fri 27 Nov
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in got]}")

    def test_pause_after_the_supervised_first_runs(self):
        # README "First live run ... small and supervised": live runs Fri 23 and Sat 24 Oct, then the owner stops the
        # keeper to fix what the summaries showed; it resumes Mon 9 Nov 06:00 (16 days of accrual), daily after
        times = [at(1), at(2)] + [at(d) for d in range(18, 34)]
        got, _ = daily(accrual_events(times), run_at(19), 8)          # Tue 10 .. Tue 17 Nov
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in got]}")

    def test_early_smoke_test_funding_then_late_launch(self):
        # a $50 processAndDistribute on Mon 26 Oct (owner smoke test of the 80/10/10 path; becomes firstAeroFundingTs),
        # the harvester's first live run Tue 10 Nov 06:00 (19.2 days of accrual), daily after
        smoke = [{"token": T.USDC, "epoch": T.epoch_start(at(4, 12)), "amount": T.usdc_raw(50.0),
                  "timestamp": at(4, 12), "blockNumber": at(4, 12) // 2}]
        times = [at(d) for d in range(19, 34)]
        got, _ = daily(smoke + accrual_events(times), run_at(20), 9)  # Wed 11 .. Thu 19 Nov
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in got]}")


# ------------------------------------------------------------------------------------------------------------------
class R6_2_FailedScanBeforeFirstAeroFundingTsIsSavedPublishesTheRunningEpoch(unittest.TestCase):
    """main.py:427-436: when the RewardFunded scan (or the one-time look-back) raises and the file has no
    firstAeroFundingTs, the bot publishes build() = the per-epoch LATEST_FUNDED figure. In the Aero era that is the
    running epoch (daily funding goes into it): a partial week, or a catch-up, annualised as a whole week (R3 H-1).
    firstAeroFundingTs is only saved by a run that took the rolling path, so the state persists while the scan fails."""

    @staticmethod
    def limited_history(days):
        # an RPC that serves eth_getLogs only for the last `days` days (public / free tiers; pruned nodes)
        return lambda frm, to, now: frm < now - days * DAY

    def test_launch_after_12_nov_with_a_three_week_log_horizon(self):
        # first live run Thu 12 Nov 06:00 (launch date open; Base forwarder still null). The main scan (<= 20.1 days)
        # is served; the look-back to 22 Oct (> 21 days) is not -> every run publishes the running epoch
        times = [at(d) for d in range(21, 45)]
        # adapted (round 6 fix): the review asserted the 15% band on every run. With no state on record the start of
        # the Aero era can't be established on this RPC, so the fixed bot publishes nothing (the file keeps the
        # harness's previous 19.2%): A asserts that nothing outside the band is ever PUBLISHED.
        got, _ = daily(accrual_events(times), run_at(22), 14, fail=self.limited_history(21))   # Fri 13 .. Thu 26 Nov
        kept = T.fresh_repo().files[T.EP]
        published = [g[:3] for g in got if g[3] != json.loads(kept).get("updatedAt")]
        self.assertFalse([g for g in published if not BAND[0] <= g[1] <= BAND[1]],
                         f"true 15%; published (day, apyPct, spanDays|mode): {published}")
        # B: the bot ran daily before the launch (from Thu 5 Nov): its state file records how far it scanned, so no
        # look-back ever reaches past the 21 days the RPC serves; from the second funding day the rate is published
        got, _ = daily(accrual_events(times), run_at(14), 22, fail=self.limited_history(21))   # Thu 5 .. Thu 26 Nov
        post = got[9:]                                                            # Sat 14 .. Thu 26 Nov
        self.assertFalse(bad(post), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in post]}")
        self.assertEqual(got[8][3], got[7][3], "Fri 13 Nov (one funding time, empty last epoch) keeps the file")

    def test_one_failed_scan_the_morning_after_a_wednesday_launch(self):
        # first live run Wed 28 Oct 06:00 (into epoch 1792627200, which holds the Aerodrome week paid 22 Oct 00:01:45);
        # the Thu 29 Oct 02:31 scan is rate limited once
        times = [at(d) for d in range(6, 20)]
        once = lambda frm, to, now: now == run_at(7)
        got, _ = daily(accrual_events(times), run_at(7), 3, fail=once)                         # Thu 29 .. Sat 31
        self.assertFalse(bad(got), f"true 15%; published (day, apyPct, spanDays|mode): {[g[:3] for g in got]}")


if __name__ == "__main__":
    unittest.main()
