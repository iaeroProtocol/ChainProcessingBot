# Review 9 (6aefe5c) repros. Each test asserts the SAFE behaviour and FAILS on 6aefe5c. No network.
# Adopted (the owner asked for these three Lows to be fixed): L1_*, L2_*, L3_*, unchanged except the import paths.
# L4 (iAERO route manipulation) and L5 (outage fallback window) are accepted as-is; I1 is not here.
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review9_findings.py
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from r9world import (Extra, MultiWorld, FrontLoadedWorld, apy_of, SAT, RUN0, T0, DAY, E22)  # noqa: E402
import test_measured_headline as tmh  # noqa: E402
import position_earnings as pe  # noqa: E402

JITTER = [0, 90, -90, 45, -45, 120, -120, 30, -30, 60, -60, 15, -15, 100, -100, 75, -75, 5, -5, 50, -50, 20, -20,
          110, -110, 35, 0, 10, -10, 70, -70, 25]
COOLDOWN = 169_200                     # LeafVoter gauge re-vote cooldown, 47 h (vote-planner/MECHANICS.md)


def kept_streak(docs):
    best = cur = 0
    for doc in docs:
        cur = cur + 1 if doc["apySource"] == "kept" else 0
        best = max(best, cur)
    return best


class L1_SpoofedClaimEventKillsTheChainRead(unittest.TestCase):
    """position_earnings.py:260-264 + 198-209: the address-less claim scan hands every emitter of a ClaimFees /
    ClaimIncentives log with topic1 = 1584 to _registered_vrms, which calls emitter.gauge() inside one Multicall3
    aggregate3. Anyone can deploy contracts that emit such a log once and burn all gas in gauge(): aggregate3 then
    reverts out of gas (probe/spoof_oog.py: >= 6 targets on Tenderly's 500M / mainnet.base.org's 600M caps, >= 3 on
    publicnode's 50M), reader.many raises, the whole Base read fails, and because the claims state is not advanced
    the same logs are rescanned and fail again on every later run."""

    def test_spoofed_claim_events_freeze_the_feed(self):
        spoofs = [(RUN0 + 9 * DAY + 3600, "0x" + format(0xdead0000 + i, "040x")) for i in range(6)]
        w = MultiWorld([], spoofs=spoofs)
        docs = [w.run(RUN0 + d * DAY) for d in range(1, 21)]
        last = docs[-1]
        self.assertNotIn(8453, last["live"]["unmeasuredChains"],
                         f"Base unmeasured on day 20 ({last.get('staleReason')})")
        self.assertLessEqual(kept_streak(docs), 1, f"headline kept {kept_streak(docs)} runs in a row; "
                                                   f"updatedAt frozen at {last['updatedAt']}")


class L2_ReVoteChurnFreezesTheHeadline(unittest.TestCase):
    """position_earnings.py:454-460 (6aefe5c's M-2 change `not g.get("active", True)`): a gauge the stake JOINED after
    the 7-day snapshot and LEFT before the current run is missing from the snapshot and inactive now, so the window is
    partial and the headline is kept. Correct data on every chain, nothing failed. With re-votes at the 47 h cooldown
    (or any cadence <= 3 days) that drop a gauge joined at the previous re-vote, every 7-day window is partial: the
    feed never publishes a fresh figure again and keeps the last one (here the day-6 since-allocation average)."""

    def test_revote_at_every_cooldown_expiry(self):
        xs = [Extra("%x" % (i + 1), 600.0, [(SAT + i * COOLDOWN, SAT + (i + 1) * COOLDOWN)]) for i in range(12)]
        w = FrontLoadedWorld(xs, revotes=[SAT + i * COOLDOWN for i in range(12)])
        docs, rows = [], []
        for d in range(1, 22):
            now = RUN0 + d * DAY + JITTER[d]
            docs.append(w.run(now))
            true = apy_of(w.true_usd_day(now))
            rows.append(f"day {d}: {docs[-1]['apySource']} {docs[-1]['apyPct']:.2f}% vs trailing {true:.2f}% "
                        f"(updatedAt {docs[-1]['updatedAt'][:10]})")
        self.assertLessEqual(kept_streak(docs), 3, "\n" + "\n".join(rows[6:]))

    def test_gauge_joined_after_the_snapshot_and_left_counts_from_zero(self):
        # unit level: snapshot S has no G (joined after S, at a re-vote recorded in lastAllocated); G earned $1,000
        # and the stake has left it by now. Its whole cumulative was earned inside the window.
        s_ts, now = 1_000_000, 1_000_000 + 7 * DAY
        snap = {"asOf": s_ts, "chains": [8453], "gauges": {"8453:a": {"fees": {"usdc": 7_000.0}}}, "complete": True}
        cur = {"asOf": now, "chains": [8453], "gauges": {"8453:a": {"active": True, "fees": {"usdc": 14_000.0}},
                                                         "8453:g": {"active": False, "fees": {"usdc": 1_000.0}}}}
        d = pe.window_delta(cur, snap, lambda cid, t: 1.0, {8453: s_ts + 4 * DAY})
        self.assertFalse(d["partial"])
        self.assertAlmostEqual(d["usdPerDay"], 8_000.0 / 7, places=6)


class L3_NewGaugeRescansFromTheFirstAllocation(unittest.TestCase):
    """position_earnings.py:279-281 (and 287-289): every VRM new to the claims state is rescanned with an address
    filter from block_at(since) (22 Oct) to the last scanned block, even when every earlier scan on that chain was
    address-less (which already saw, and would have discovered, any claim from it). Each re-vote that adds a gauge
    rescans the whole history: 3.45 eth_getLogs per 1,000 Base blocks on Tenderly (probe/logcost.py: 690 calls,
    76 s for 200k blocks), i.e. ~4,500 calls per month of history at 2 s blocks and ~10x that with 200 ms blocks."""

    def test_no_rescan_below_the_address_less_scans(self):
        g = Extra("9", 600.0, [(T0 + 30 * DAY, 10 ** 12)])            # joined on day 30
        w = MultiWorld([g], revotes=[T0 + 30 * DAY])
        for d in range(1, 32):
            if d == 30:
                w.log_calls.clear()                                   # the day-30 run reads the new gauge first
            w.run(RUN0 + d * DAY)
        since_block = w.sims[8453].block_of(T0)
        rescans = [c for c in w.log_calls if c[0] == 8453 and not c[1] and c[2] <= since_block]
        self.assertEqual(rescans, [], f"day 30 rescans {[(c[3] - c[2]) for c in rescans]} blocks from the first "
                                      f"allocation with an address filter")


if __name__ == "__main__":
    unittest.main()
