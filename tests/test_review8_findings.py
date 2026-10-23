# Review 8 (c4754fb, measured headline): repros. Each test asserts the SAFE behaviour and fails on c4754fb.
# Reuses the author's simulated world (tests/test_measured_headline.py). No network.
# Adopted: M1_* and M2_* (Mediums); the review's L1-L5 (Lows) are not here. Adaptations are marked "adapted"; the
# last M2 test is the author's (discovery from a claim).
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review8_findings.py
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import test_measured_headline as tmh  # noqa: E402
from test_measured_headline import (World, SimChain, SimReader, FakePF, daily_harvests, daily_fundings,  # noqa: E402
                                    usd_per_day, _addr, TRUE_APY, PRICES, STAKED_USD, RUN0, T0, E22, DAY, WEEK,
                                    E18, YH, WETH, USDC, AERO)
import position_earnings as pe  # noqa: E402

NOTSET = object()


class HookReader(SimReader):
    """SimReader plus per-chain hooks that see (reader, target, sig, args) and may answer instead of the sim."""
    hooks = {}

    def many(self, calls):
        fn = self.hooks.get(self.chain_id)
        out = []
        for t, sig, args, _ in calls:
            v = fn(self, (t or "").lower(), sig, list(args)) if fn else NOTSET
            out.append(self._one((t or "").lower(), sig) if v is NOTSET else v)
        return out


def hooked(hooks):
    HookReader.hooks = hooks
    return mock.patch.object(tmh, "SimReader", HookReader)


def apy_of(usd_day):
    return usd_day * 365 * 0.8 / STAKED_USD * 100


# Today's measured profile of #1584 on Base (review8/probe/rate_now.py, 22 Oct): hours 3-15 after the allocation
# ~$3.5k/day, then ~$2.0k/day (its vote share on its gauges fell 9.9% -> 3.3% in 18 h; allocated power +50% since
# 14:00), and the 2-day launch programs (~$0.95k/day) end 24 Oct 01:00-07:00 -> ~$1.1k/day of fees after.
# Relative to the post-launch rate R: day 0 ~2.67 R, day 1 ~1.86 R, then R (no further dilution assumed).
PROFILE = ((DAY, 2.67), (2 * DAY, 1.86))


DECLINE = {"k": 0.0}     # optional further decline after day 2: rate R * (1 - k * days since day 2)


def integ(e):
    """Seconds-at-rate-R earned in the first e seconds after the allocation."""
    f, prev = 0.0, 0
    for bound, m in PROFILE:
        seg = min(e, bound) - prev
        if seg > 0:
            f += seg * m
        prev = bound
    x = max(0, e - prev) / DAY
    return f + (x - DECLINE["k"] * x * x / 2) * DAY


class DecliningChain(SimChain):
    def accrued(self, ts):
        e = integ(max(0, int(ts) - T0))
        return {("fee", self.t0): int(self.r0 * e), ("fee", self.t1): int(self.r1 * e), ("inc", self.inc): int(self.ri * e)}


def true_trailing_apy(d):
    e = RUN0 + d * DAY - T0
    return apy_of(usd_per_day() * (integ(e) - integ(e - 7 * DAY)) / (7 * DAY))


class M1_SinceAllocationFallbackAfterWeekOne(unittest.TestCase):
    """realized_yield.py:157-161 + position_earnings.py:343-346: after week 1, any day whose 7-day snapshot is
    incomplete (or missing) publishes the since-allocation (lifetime) average as a fresh measured figure."""

    def test_incomplete_7d_snapshot_publishes_the_lifetime_average(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        w.sims = {cid: DecliningChain(cid) for cid in (8453, 1, 4663)}
        docs = []
        for d in range(11):
            # a 2-day Robinhood RPC outage on Sat 24 / Sun 25 Oct (days 2-3): those days keep the headline (fine)
            docs.append(w.run(RUN0 + d * DAY, unreachable=(4663,) if d in (2, 3) else ()))
        bad = []
        for d in (8, 9, 10):
            doc, true = docs[d], true_trailing_apy(d)
            # adapted: the review checked that the window ended at the incomplete 7-day-old point (days 9 and 10);
            # with the fix it ends at the closest COMPLETE point 6-8 days old
            snap = doc["live"]["trailing"]["7d"]
            self.assertTrue(snap["complete"])
            self.assertTrue(RUN0 + (d - 8) * DAY <= snap["snapshotAsOf"] <= RUN0 + (d - 6) * DAY)
            # the stake earns R on days 2-10 (trailing 7d at day 9 and 10 = R); published must be within 25% of it
            if doc["apyPct"] > true * 1.25:
                bad.append(f"day {d}: {doc['apySource']} {doc['apyPct']:.2f}% vs trailing {true:.2f}% "
                           f"(+{(doc['apyPct'] / true - 1) * 100:.1f}%)")
        self.assertEqual(bad, [])

    def test_with_a_steady_3pct_a_day_decline_every_fallback_day_is_over(self):
        # the stake's vote share on its gauges fell 35% between 08:00 and 20:50 on 22 Oct; 3%/day is milder
        DECLINE["k"] = 0.03
        try:
            w = World(harvests=daily_harvests(), fundings=daily_fundings())
            w.sims = {cid: DecliningChain(cid) for cid in (8453, 1, 4663)}
            docs = [w.run(RUN0 + d * DAY, unreachable=(1,) if d in (5, 9) else ()) for d in range(17)]
            bad = []
            for d in (12, 16):          # Ethereum publicnode down on days 5 and 9 -> fallbacks on days 12 and 16
                true = true_trailing_apy(d)
                if docs[d]["apyPct"] > true * 1.25:
                    bad.append(f"day {d}: {docs[d]['apySource']} {docs[d]['apyPct']:.2f}% vs trailing {true:.2f}% "
                               f"(+{(docs[d]['apyPct'] / true - 1) * 100:.1f}%)")
            self.assertEqual(bad, [])
        finally:
            DECLINE["k"] = 0.0

    def test_closest_incomplete_point_is_chosen_over_a_complete_neighbour(self):
        now = RUN0 + 20 * DAY
        hist = [{"asOf": now - 8 * DAY + 600, "complete": True},     # 7.99 d old, complete
                {"asOf": now - 7 * DAY, "complete": False},          # 7.00 d old, one chain failed that day
                {"asOf": now - 6 * DAY - 600, "complete": True}]     # 6.01 d old, complete
        snap = pe.pick_snapshot(hist, now, "7d")
        self.assertTrue(snap["complete"], "a complete 6-8 d point exists, but the incomplete one is chosen")


class M2_GaugesLeftBeforeTheFirstRunAreNeverMeasured(unittest.TestCase):
    """position_earnings.py:161-166, 642-646: gauges come from allocatedGauges + the previous live block only. If the
    bot first runs after the owner's Sat 24 Oct re-vote, the gauges #1584 left are never read: their day 0-2
    earnings (claimed or not) are missing from the since-allocation numerator."""

    def test_first_run_after_the_re_vote_understates(self):
        LEAVE = T0 + 2 * DAY - 3600                 # Sat 24 Oct 01:11 (cooldown expiry)
        G2, V2, P2 = _addr("a2", 8453), _addr("b2", 8453), _addr("c2", 8453)   # left at the re-vote
        G3, V3, P3 = _addr("a3", 8453), _addr("b3", 8453), _addr("c3", 8453)   # voted at the re-vote
        R = 10_416                                  # raw USDC/s: $900/day on each of G2 (before) and G3 (after)
        base = None

        def hook(rd, target, sig, args):
            ts = rd.block_ts
            if sig == "allocatedGauges(uint256)":
                return [tmh.Web3.to_checksum_address(g) for g in ([base.gauge, G2] if ts < LEAVE else [base.gauge, G3])]
            if sig == "tokenStates(uint256)":
                return (pe.ZERO, T0 if ts < LEAVE else LEAVE, False, 1_000_000 * E18)
            g = {G2: (V2, P2, T0, LEAVE), G3: (V3, P3, LEAVE, 10 ** 12)}
            if target in (G2, G3) or (sig == "gaugeToRewards(address)" and args[0].lower() in (G2, G3)):
                gg = target if target in (G2, G3) else args[0].lower()
                return {"votingRewardsManager()": g[gg][0], "gaugeToRewards(address)": g[gg][0], "pool()": g[gg][1],
                        "stakingToken()": None}.get(sig, NOTSET)
            if sig == "allocations(uint256,address)" and args[1].lower() in (G2, G3):
                return 500_000 * E18
            for v, p, start, end in g.values():
                if target == v:
                    earned = R * max(0, min(ts, end) - start)
                    return {"token0()": USDC, "token1()": WETH, "earnedFees(uint256,uint256)": (earned, 0),
                            "incentiveCount()": 0}.get(sig, NOTSET)
                if target == p and sig == "tickSpacing()":
                    return 100
            return NOTSET

        # adapted: the config lists #1584's first-allocation gauges (FIRST_ALLOCATION_GAUGES); in this world that is
        # the sim's gauge and G2
        w = World(harvests=daily_harvests(), fundings=daily_fundings(), first_gauges={8453: [G2]})
        base = w.sims[8453]
        with hooked({8453: hook}):
            docs = {d: w.run(RUN0 + d * DAY) for d in range(2, 5)}      # first run: Sat 24 Oct 02:31
        bad = []
        for d in (2, 3, 4):
            true = apy_of(usd_per_day() + 900.0)                      # the stake always earns +$900/day on G2 or G3
            self.assertEqual(docs[d]["apySource"], "measured-since-allocation")
            if docs[d]["apyPct"] < true * 0.75:
                bad.append(f"day {d}: {docs[d]['apyPct']:.2f}% vs true {true:.2f}% "
                           f"({(docs[d]['apyPct'] / true - 1) * 100:.1f}%)")
        self.assertEqual(bad, [])


class M2_GaugeFoundFromAClaim(unittest.TestCase):
    """Author's test for M-2's second part: a gauge the stake left between two runs (so neither allocatedGauges nor the
    previous live block nor the config lists it) is found from the harvester's claim on its VRM and measured."""

    def test_claim_reveals_a_gauge_left_between_runs(self):
        G2, V2, P2 = _addr("a2", 8453), _addr("b2", 8453), _addr("c2", 8453)
        ON, OFF = RUN0 + 3 * DAY + 3600, RUN0 + 3 * DAY + 7200      # allocated and left between the day-3 and day-4 runs
        CLAIM = RUN0 + 4 * DAY + 600                                # the harvester claims G2's rewards before day 5
        R = 10_416 * 24                                             # raw USDC/s while allocated: $900 an hour
        earned = lambda ts: R * max(0, min(ts, OFF) - ON)
        logs = []

        class ClaimReader(HookReader):
            def logs(self, addresses, topics, from_block, to_block=None, **kw):
                out = SimReader.logs(self, addresses, topics, from_block, to_block)
                if out is None:
                    return None
                tb = self.block if to_block is None else min(to_block, self.block)
                want = None if addresses is None else {a.lower() for a in addresses}
                return out + [lg for b, lg in logs if from_block <= b <= tb and (want is None or V2 in want)]

        def hook(rd, target, sig, args):
            ts = rd.block_ts
            claimed = earned(CLAIM) if ts >= CLAIM else 0
            if sig == "allocatedGauges(uint256)":
                return [tmh.Web3.to_checksum_address(g) for g in ([rd.sim.gauge, G2] if ON <= ts < OFF else [rd.sim.gauge])]
            if target == V2:
                return {"gauge()": G2, "token0()": USDC, "token1()": WETH, "incentiveCount()": 0,
                        "earnedFees(uint256,uint256)": (earned(ts) - claimed, 0)}.get(sig, NOTSET)
            if target == G2:
                return {"votingRewardsManager()": V2, "pool()": P2}.get(sig, NOTSET)
            if target == P2 and sig == "tickSpacing()":
                return 100
            if args and str(args[-1]).lower() == G2:
                return {"gaugeToRewards(address)": V2, "allocations(uint256,address)": 0,
                        "gaugeStates(address)": (0, 0, 0, True, True, 0, 0, 0, 0, 0, 0, 0)}.get(sig, NOTSET)
            return NOTSET

        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        b = w.sims[8453].block_of(CLAIM)
        logs.append((b, {"address": tmh.Web3.to_checksum_address(V2),
                         "topics": [bytes.fromhex(pe.CLAIM_FEES_TOPIC[2:]), (1584).to_bytes(32, "big"), bytes(32),
                                    bytes(12) + bytes.fromhex(USDC[2:])],
                         "data": earned(CLAIM).to_bytes(32, "big"), "blockNumber": b}))
        HookReader.hooks = {8453: hook}
        with mock.patch.object(tmh, "SimReader", ClaimReader):
            docs = {d: w.run(RUN0 + d * DAY) for d in range(6)}
        g2 = [g for g in docs[5]["live"]["gauges"] if g["gauge"] == G2]
        self.assertEqual(len(g2), 1, "G2 never read")
        self.assertAlmostEqual(g2[0]["accruedUSD"], earned(OFF) / 1e6, places=4)      # claimed + unclaimed
        self.assertIn(G2, json.loads(w.repo.files[tmh.LS])["chains"]["8453"]["gauges"])
        true = apy_of(usd_per_day() + earned(OFF) / 1e6 / ((RUN0 + 5 * DAY - T0) / DAY))
        self.assertEqual(docs[5]["apySource"], "measured-since-allocation")
        self.assertAlmostEqual(docs[5]["apyPct"], true, delta=true * 1e-4)


if __name__ == "__main__":
    unittest.main()
