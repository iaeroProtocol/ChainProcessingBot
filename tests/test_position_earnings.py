# test_position_earnings.py
# Unit tests for the protocol stake's live earnings (`live` block of estimated_rewards_usd.json). No network.
# Run: python -m unittest discover -s tests
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from eth_utils import keccak  # noqa: E402
from web3 import Web3  # noqa: E402

import position_earnings as pe  # noqa: E402

E18 = 10 ** 18
DAY = 86400
T0 = 1792635063                     # #1584 first allocation
NOW = T0 + DAY // 2                 # half a day later
LV = pe.LEAF_VOTER.lower()
REG = pe.FACTORY_REGISTRY_BASE.lower()
AERO = "0x3f5bf3edac59d650d8fdf9657a71f2f904a3a4ee"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
WETH = "0x4200000000000000000000000000000000000006"
G_CL, VRM_CL, POOL_CL = "0x" + "a1" * 20, "0x" + "b1" * 20, "0x" + "c1" * 20
G_V2, VRM_V2, POOL_V2 = "0x" + "a2" * 20, "0x" + "b2" * 20, "0x" + "c2" * 20
G_OLD, VRM_OLD = "0x" + "a3" * 20, "0x" + "b3" * 20


class FakeReader:
    """Answers ChainReader.many() from a dict {(target, sig, args): value}; missing -> None (call failed)."""

    def __init__(self, answers, chain_id=8453, logs=None, block=1000, block_ts=NOW):
        self.answers, self.chain_id, self.block, self.block_ts = answers, chain_id, block, block_ts
        self._logs, self.log_calls = logs, []

    def many(self, calls):
        return [self.answers.get((t.lower() if t else t, sig, tuple(a.lower() if isinstance(a, str) else a for a in args)))
                for t, sig, args, _ in calls]

    def block_at(self, ts):
        return 1

    def logs(self, addresses, topics, from_block, step=10_000):
        self.log_calls.append((sorted(a.lower() for a in addresses), topics, from_block))
        return self._logs


def base_answers(trunc=False):
    a = {
        (LV, "allocatedGauges(uint256)", (1584,)): [Web3.to_checksum_address(G_CL), Web3.to_checksum_address(G_V2)],
        (LV, "tokenStates(uint256)", (1584,)): (pe.ZERO, T0, False, 900 * E18),
        (LV, "allocations(uint256,address)", (1584, G_CL)): 600 * E18,
        (LV, "allocations(uint256,address)", (1584, G_V2)): 300 * E18,
        # CL gauge: pool(); registry VRM wins over the gauge's own pointer
        (G_CL, "votingRewardsManager()", ()): "0x" + "ee" * 20,
        (REG, "gaugeToRewards(address)", (G_CL,)): VRM_CL,
        (G_CL, "pool()", ()): POOL_CL,
        # v2 gauge: no pool(), the LP token is stakingToken(); no registry entry -> gauge pointer
        (G_V2, "votingRewardsManager()", ()): VRM_V2,
        (G_V2, "stakingToken()", ()): POOL_V2,
        (VRM_CL, "token0()", ()): WETH, (VRM_CL, "token1()", ()): USDC,
        (VRM_V2, "token0()", ()): AERO, (VRM_V2, "token1()", ()): USDC,
        (VRM_CL, "earnedFees(uint256,uint256)", (1584, 10_000)): (1 * E18 // 100, 30 * 10**6),
        (VRM_CL, "earnedFees(uint256,uint256)", (1584, 20_000)): ((2 if trunc else 1) * E18 // 100, 30 * 10**6),
        (VRM_V2, "earnedFees(uint256,uint256)", (1584, 10_000)): (10 * E18, 5 * 10**6),
        (VRM_V2, "earnedFees(uint256,uint256)", (1584, 20_000)): (10 * E18, 5 * 10**6),
        (VRM_CL, "incentiveCount()", ()): 1, (VRM_V2, "incentiveCount()", ()): 2,
        (POOL_CL, "tickSpacing()", ()): 100,
        (VRM_CL, "incentive(uint256)", (1,)): (AERO, 0, 0, T0 - 3600, T0 + 2 * DAY, pe.ZERO),
        (VRM_CL, "earnedIncentives(uint256,uint256,uint256)", (1584, 1, 10_000)): 100 * E18,
        (VRM_CL, "earnedIncentives(uint256,uint256,uint256)", (1584, 1, 20_000)): 100 * E18,
        (VRM_V2, "incentive(uint256)", (1,)): (AERO, 0, 0, T0, T0 + 2 * DAY, pe.ZERO),
        (VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 1, 10_000)): 50 * E18,
        (VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 1, 20_000)): 50 * E18,
        (VRM_V2, "incentive(uint256)", (2,)): (USDC, 0, 0, T0, T0 + 2 * DAY, pe.ZERO),
        (VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 2, 10_000)): 7 * 10**6,
        (VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 2, 20_000)): 7 * 10**6,
    }
    return a


def _log(addr, topic0, t3, amount):
    tid = "0x" + (1584).to_bytes(32, "big").hex()
    return {"address": Web3.to_checksum_address(addr), "topics": [bytes.fromhex(topic0[2:]), bytes.fromhex(tid[2:]),
            bytes(32), t3], "data": amount.to_bytes(32, "big")}


class ReadChainPositionTest(unittest.TestCase):
    def test_reads_gauges_fees_incentives_and_claims(self):
        claims = [
            _log(VRM_V2, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 2 * 10**6),
            _log(VRM_V2, pe.CLAIM_INCENTIVES_TOPIC, (1).to_bytes(32, "big"), 4 * E18),
        ]
        r = FakeReader(base_answers(), logs=claims)
        ch = pe.read_chain_position(r, 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertEqual((ch["since"], ch["lastAllocated"], ch["chainAllocation"], ch["claimsScanned"]), (T0, T0, 900 * E18, True))
        cl, v2 = ch["gauges"]
        self.assertEqual((cl["vrm"], cl["pool"], cl["kind"], cl["allocation"], cl["active"]), (VRM_CL, POOL_CL, "CL100", 600 * E18, True))
        self.assertEqual((v2["vrm"], v2["pool"], v2["kind"]), (VRM_V2, POOL_V2, "v2"))
        self.assertEqual(cl["fees"], {WETH: E18 // 100, USDC: 30 * 10**6})      # VRM token0/token1 order
        self.assertEqual([(x["programId"], x["token"], x["amount"]) for x in v2["incentives"]],
                         [(1, AERO, 50 * E18), (2, USDC, 7 * 10**6)])
        self.assertEqual(v2["claimed"], {USDC: 2 * 10**6, AERO: 4 * E18})
        self.assertFalse(cl["truncated"])
        # one filter for all VRMs, both claim events, indexed tokenId
        addrs, topics, _ = r.log_calls[0]
        self.assertEqual(addrs, sorted([VRM_CL, VRM_V2]))
        self.assertEqual(topics[0], [pe.CLAIM_FEES_TOPIC, pe.CLAIM_INCENTIVES_TOPIC])
        self.assertEqual(topics[1], "0x" + (1584).to_bytes(32, "big").hex())

    def test_truncation_is_detected_and_the_larger_window_used(self):
        cl = pe.read_chain_position(FakeReader(base_answers(trunc=True), logs=[]), 1584, registry=pe.FACTORY_REGISTRY_BASE)["gauges"][0]
        self.assertTrue(cl["truncated"])
        self.assertEqual(cl["fees"][WETH], 2 * E18 // 100)

    def test_refused_logs_mean_claims_unknown(self):
        ch = pe.read_chain_position(FakeReader(base_answers(), logs=None), 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertFalse(ch["claimsScanned"])
        self.assertTrue(all(g["claimed"] == {} for g in ch["gauges"]))

    def test_revote_keeps_first_allocation_and_previous_gauges(self):
        a = base_answers()
        a[(LV, "tokenStates(uint256)", (1584,))] = (pe.ZERO, T0 + 2 * DAY, False, 900 * E18)  # re-voted Sat
        a[(G_OLD, "votingRewardsManager()", ())] = VRM_OLD
        a[(VRM_OLD, "token0()", ())] = AERO
        a[(VRM_OLD, "token1()", ())] = USDC
        a[(VRM_OLD, "earnedFees(uint256,uint256)", (1584, 10_000))] = (3 * E18, 0)
        a[(VRM_OLD, "earnedFees(uint256,uint256)", (1584, 20_000))] = (3 * E18, 0)
        ch = pe.read_chain_position(FakeReader(a, logs=[]), 1584, registry=pe.FACTORY_REGISTRY_BASE, extra_gauges=(G_OLD,))
        self.assertEqual(ch["since"], T0)                       # not the re-vote time
        old = [g for g in ch["gauges"] if g["gauge"] == G_OLD][0]
        self.assertEqual((old["active"], old["allocation"], old["fees"][AERO]), (False, 0, 3 * E18))
        # a different stake id has no known first allocation -> its own lastAllocated
        a[(LV, "tokenStates(uint256)", (77,))] = (pe.ZERO, T0 + 5, False, 1)
        self.assertEqual(pe.read_chain_position(FakeReader(a, logs=[]), 77)["since"], T0 + 5)


def _chain(cid, since, ts, alloc, gauges):
    return {"chainId": cid, "block": 1, "blockTimestamp": ts, "since": since, "lastAllocated": since,
            "chainAllocation": alloc, "claimsScanned": True, "gauges": gauges}


def _gauge(g, alloc, fees=None, inc=None, claimed=None, t0=WETH, t1=USDC):
    return {"gauge": g, "vrm": "0x" + "99" * 20, "pool": "0x" + "98" * 20, "token0": t0, "token1": t1, "kind": "CL100",
            "allocation": alloc, "active": True, "truncated": False, "fees": fees or {},
            "incentives": [{"programId": 1, "token": t, "amount": a} for t, a in (inc or {}).items()], "claimed": claimed or {}}


META = {8453: {AERO: {"symbol": "AERO", "decimals": 18}, USDC: {"symbol": "USDC", "decimals": 6},
               WETH: {"symbol": "WETH", "decimals": 18}},
        1: {"0xweth": {"symbol": "WETH", "decimals": 18}, "0xusdt": {"symbol": "USDT", "decimals": 6}}}
PRICES = {8453: {AERO: 0.8, USDC: 1.0, WETH: 4000.0}, 1: {"0xweth": 4000.0, "0xusdt": 1.0}}


class ValueLiveTest(unittest.TestCase):
    def test_accrual_rate_and_both_annualisations(self):
        chains = [
            _chain(8453, T0, T0 + DAY // 2, 85_000 * E18, [
                _gauge(G_CL, 85_000 * E18, fees={WETH: E18 // 100, USDC: 10 * 10**6}, inc={AERO: 100 * E18},
                       claimed={USDC: 10 * 10**6})]),                                     # $40 + $10 + $80 + $10 = $140
            _chain(1, T0, T0 + DAY, 10_000 * E18, [
                _gauge("0x" + "dd" * 20, 10_000 * E18, fees={"0xweth": E18 // 100, "0xusdt": 20 * 10**6}, t0="0xweth", t1="0xusdt")]),  # $60
        ]
        live = pe.value_live(chains, META, PRICES, 1584, staked_aero_raw=100_000 * E18, aero_price=0.8,
                             staked_iaero_usd=60_000.0, stakers_bps=8000, now_ts=T0 + DAY)
        self.assertAlmostEqual(live["accruedUSD"], 200.0)
        self.assertAlmostEqual(live["feesUSD"], 40 + 10 + 40 + 20)
        self.assertAlmostEqual(live["incentivesUSD"], 80.0)
        self.assertAlmostEqual(live["claimedUSD"], 10.0)
        b, e = live["gauges"]
        self.assertAlmostEqual(b["usdPerDay"], 280.0)        # $140 over half a day
        self.assertAlmostEqual(e["usdPerDay"], 60.0)         # $60 over a day
        self.assertAlmostEqual(live["usdPerDay"], 340.0)
        self.assertAlmostEqual(live["annualUSD"], 340.0 * 365)
        self.assertAlmostEqual(live["positionAprPct"], 340.0 * 365 / (100_000 * 0.8) * 100)       # 155.1%
        self.assertAlmostEqual(live["projectedStakerApyPct"], 340.0 * 365 * 0.8 / 60_000.0 * 100)  # 165.5%
        self.assertAlmostEqual(live["measuredShareOfAllocation"], 0.95)
        self.assertEqual(live["unmeasuredChains"], [4663])
        self.assertEqual(b["label"], "WETH/USDC CL100")
        self.assertAlmostEqual(b["allocationShare"], 0.85)
        self.assertEqual(live["method"], "live_position")
        self.assertIn("positionAprPct", live["definitions"])

    def test_unpriced_tokens_listed(self):
        chains = [_chain(8453, T0, NOW, 1, [_gauge(G_CL, 1, inc={"0x" + "77" * 20: E18})])]
        live = pe.value_live(chains, META, PRICES, 1584, 1000 * E18, 0.8, 600.0, now_ts=NOW)
        self.assertEqual(live["unpricedTokens"], ["8453:0x" + "77" * 20])
        self.assertEqual(live["accruedUSD"], 0.0)

    def test_sanity_guard_omits_spikes(self):
        chains = [_chain(8453, T0, T0 + 60, 1, [_gauge(G_CL, 1, inc={AERO: 1_000_000 * E18})])]  # absurd minute
        with self.assertLogs("position_earnings", "WARNING"):
            live = pe.value_live(chains, META, PRICES, 1584, 1000 * E18, 0.8, 600.0, now_ts=T0 + 60)
        self.assertNotIn("positionAprPct", live)
        self.assertNotIn("projectedStakerApyPct", live)
        self.assertGreater(live["accruedUSD"], 0)          # raw numbers still shown

    def test_missing_denominators_are_omitted(self):
        live = pe.value_live([], META, PRICES, 1584, 0, 0.8, 0.0, now_ts=NOW)
        self.assertNotIn("positionAprPct", live)
        self.assertNotIn("projectedStakerApyPct", live)


def _g2(g, fees=None, inc=None, cfees=None, cinc=None, active=True):
    """Gauge row with separate claimed fees / incentives (raw units)."""
    r = _gauge(g, 1, fees=fees, inc=inc)
    r["active"] = active
    r["claimedFees"], r["claimedIncentives"] = dict(cfees or {}), dict(cinc or {})
    r["claimed"] = {t: (cfees or {}).get(t, 0) + (cinc or {}).get(t, 0) for t in set(cfees or {}) | set(cinc or {})}
    return r


def _live(gauges, now, history=None, prices=PRICES, chains_extra=()):
    chains = [_chain(8453, T0, now, 1, gauges)] + list(chains_extra)
    return pe.value_live(chains, META, prices, 1584, 1_000_000 * E18, 0.8, 600_000.0, now_ts=now, prev_history=history)


class TrailingTest(unittest.TestCase):
    NOW = T0 + 10 * DAY

    def point(self, ago, usdc_fees, aero_inc, gauge=G_CL, extra=None):
        """History point `ago` seconds before NOW with cumulative USDC fees and AERO incentives (human units)."""
        g = {f"8453:{gauge}": {"usd": 0, "fees": {USDC: usdc_fees}, "incentives": {AERO: aero_inc}}}
        g.update(extra or {})
        return {"asOf": self.NOW - ago, "chains": [8453], "accruedUSD": 0, "feesCumUSD": 0, "gauges": g}

    def test_windows_are_null_without_history_and_a_point_is_recorded(self):
        live = _live([_g2(G_CL, fees={USDC: 100 * 10**6}, inc={AERO: 50 * E18})], self.NOW)
        self.assertEqual(live["trailing"], {"24h": None, "7d": None})
        self.assertEqual(live["feesOnly"]["trailing"], {"24h": None, "7d": None})
        self.assertAlmostEqual(live["feesOnly"]["usdPerDay"], 100 / 10)           # $100 fees over 10 days
        self.assertEqual(live["alerts"], [])
        (pt,) = live["history"]
        self.assertEqual(pt["gauges"][f"8453:{G_CL}"]["fees"], {USDC: 100.0})
        self.assertEqual(pt["gauges"][f"8453:{G_CL}"]["incentives"], {AERO: 50.0})
        self.assertEqual((pt["asOf"], pt["chains"]), (self.NOW, [8453]))

    def test_24h_and_7d_rates_use_the_right_snapshots(self):
        hist = [self.point(9 * DAY, 0, 0), self.point(7 * DAY + 3600, 30, 100), self.point(5 * DAY, 50, 150),
                self.point(DAY + 600, 90, 240)]
        live = _live([_g2(G_CL, fees={USDC: 100 * 10**6}, inc={AERO: 250 * E18})], self.NOW, hist)
        t24, t7 = live["trailing"]["24h"], live["trailing"]["7d"]
        self.assertEqual((t24["snapshotAsOf"], t24["snapshotAgeHours"]), (self.NOW - DAY - 600, round((DAY + 600) / 3600, 2)))
        self.assertEqual(t7["snapshotAsOf"], self.NOW - 7 * DAY - 3600)         # 6-8 d old; 5 d and 9 d ignored
        d24 = (DAY + 600) / DAY
        self.assertAlmostEqual(t24["usdPerDay"], (10 * 1.0 + 10 * 0.8) / d24)    # +10 USDC fees, +10 AERO incentives
        d7 = (7 * DAY + 3600) / DAY
        self.assertAlmostEqual(t7["usdPerDay"], (70 + 150 * 0.8) / d7)
        self.assertAlmostEqual(t7["positionAprPct"], t7["usdPerDay"] * 365 / (1_000_000 * 0.8) * 100)
        self.assertAlmostEqual(t7["projectedStakerApyPct"], t7["usdPerDay"] * 365 * 0.8 / 600_000 * 100)
        self.assertAlmostEqual(live["feesOnly"]["trailing"]["24h"]["usdPerDay"], 10 / d24)
        self.assertAlmostEqual(live["feesOnly"]["trailing"]["7d"]["usdPerDay"], 70 / d7)
        self.assertAlmostEqual(live["gauges"][0]["usdPerDay24h"], t24["usdPerDay"])
        self.assertTrue(t24["claimsComplete"])
        self.assertFalse(t24["partial"])

    def test_claims_are_cumulative_not_negative(self):
        # yesterday 90 USDC unclaimed; since then 100 USDC claimed and 5 more accrued
        hist = [self.point(DAY, 90, 0)]
        live = _live([_g2(G_CL, fees={USDC: 5 * 10**6}, cfees={USDC: 100 * 10**6})], self.NOW, hist)
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 15.0)
        self.assertFalse([a for a in live["alerts"] if a["type"] == "negative_delta"])

    def test_price_moves_do_not_leak_into_the_rate(self):
        hist = [self.point(DAY, 100, 1000)]
        cheap = {8453: dict(PRICES[8453], **{AERO: 0.4})}
        live = _live([_g2(G_CL, fees={USDC: 100 * 10**6}, inc={AERO: 1000 * E18})], self.NOW, hist, prices=cheap)
        self.assertEqual(live["trailing"]["24h"]["usdPerDay"], 0.0)

    def test_alerts_zero_gauge_drop_and_negative(self):
        G2 = "0x" + "a9" * 20
        other = {f"8453:{G2}": {"fees": {USDC: 500.0}, "incentives": {}}}
        hist = [self.point(7 * DAY, 0, 0, extra={f"8453:{G2}": {"fees": {USDC: 0.0}, "incentives": {}}}),
                self.point(DAY, 600, 0, extra=other)]
        live = _live([_g2(G_CL, fees={USDC: 610 * 10**6}),         # +10 in 24h vs ~87/day over 7d -> drop
                      _g2(G2, fees={USDC: 400 * 10**6})],          # 500 -> 400: negative (claims missed), clamped
                     self.NOW, hist)
        types = sorted(a["type"] for a in live["alerts"])
        self.assertEqual(types, ["fees_rate_drop", "gauge_no_earnings_24h", "negative_delta", "rate_drop"])
        zero = [a for a in live["alerts"] if a["type"] == "gauge_no_earnings_24h"][0]
        self.assertEqual(zero["gauge"], G2)
        drop = [a for a in live["alerts"] if a["type"] == "rate_drop"][0]
        self.assertGreater(drop["dropPct"], 50)
        with self.assertLogs("position_earnings", "WARNING") as logs:
            _live([_g2(G_CL, fees={USDC: 610 * 10**6}), _g2(G2, fees={USDC: 400 * 10**6})], self.NOW, hist)
        self.assertTrue(any("ALERT rate_drop" in m for m in logs.output))

    def test_trickle_counts_as_nothing_but_unpriced_earnings_do_not(self):
        X = "0x" + "77" * 20
        hist = [self.point(DAY, 90, 0, extra={f"8453:{G_V2}": {"fees": {X: 1.0}, "incentives": {}}})]
        live = _live([_g2(G_CL, fees={USDC: 90 * 10**6 + 300_000}),     # +$0.30 in a day -> "nothing"
                      _g2(G_V2, fees={X: 5 * E18})],                     # unpriced token kept accruing -> no alert
                     self.NOW, hist)
        zero = [a for a in live["alerts"] if a["type"] == "gauge_no_earnings_24h"]
        self.assertEqual([a["gauge"] for a in zero], [G_CL])
        self.assertAlmostEqual(zero[0]["usdPerDay24h"], 0.3)

    def test_inactive_gauge_with_no_earnings_is_not_alerted(self):
        live = _live([_g2(G_CL, fees={USDC: 90 * 10**6}, active=False)], self.NOW, [self.point(DAY, 90, 0)])
        self.assertEqual(live["alerts"], [])

    def test_history_cadence_and_cap(self):
        hist = [self.point(d * DAY, d, 0) for d in range(14, 0, -1)] + [self.point(3 * 3600, 0.5, 0)]
        live = _live([_g2(G_CL, fees={USDC: 1 * 10**6})], self.NOW, hist)
        ages = [self.NOW - h["asOf"] for h in live["history"]]
        self.assertEqual(ages[-1], 0)                                   # current run appended
        self.assertNotIn(3 * 3600, ages)                                # a point < 12 h old is replaced
        self.assertTrue(all(a <= 10.5 * DAY for a in ages))
        self.assertLessEqual(len(ages), pe.HISTORY_MAX_POINTS)

    def test_partial_chain_coverage_is_excluded_and_flagged(self):
        eth = _chain(1, T0, self.NOW, 1, [_g2("0x" + "dd" * 20, fees={USDC: 10 * 10**6})])
        hist = [self.point(DAY, 90, 0)]                                  # Ethereum wasn't measured yesterday
        live = _live([_g2(G_CL, fees={USDC: 100 * 10**6})], self.NOW, hist, chains_extra=[eth])
        self.assertTrue(live["trailing"]["24h"]["partial"])
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 10.0)   # Base only
        self.assertIn(f"1:{'0x' + 'dd' * 20}", live["history"][-1]["gauges"])

    def test_spikes_in_trailing_rates_are_omitted(self):
        hist = [self.point(DAY, 0, 0)]
        with self.assertLogs("position_earnings", "WARNING"):
            live = _live([_g2(G_CL, inc={AERO: 50_000_000 * E18})], self.NOW, hist)
        self.assertIn("usdPerDay", live["trailing"]["24h"])
        self.assertNotIn("positionAprPct", live["trailing"]["24h"])


class BuildLiveTest(unittest.TestCase):
    def test_failed_chain_is_reported_unmeasured_and_prev_gauges_reused(self):
        good = FakeReader(base_answers(), logs=[])
        bad = mock.Mock(chain_id=1)
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        orig = pe.read_chain_position

        def read(reader, *a, **k):
            if reader is bad:
                raise RuntimeError("rpc down")
            return orig(reader, *a, **k)
        with mock.patch.object(pe, "read_chain_position", side_effect=read) as rcp, \
             mock.patch.object(pe, "token_meta", return_value=META[8453]):
            live = pe.build_live([(good, pe.FACTORY_REGISTRY_BASE), (bad, None)], 1584, {8453: pf}, 1000 * E18, 0.8, 600.0,
                                 prev_live={"stakeId": 1584, "gauges": [{"chainId": 8453, "gauge": G_OLD}]}, now_ts=NOW)
            self.assertEqual(rcp.call_args_list[0].kwargs["extra_gauges"], (G_OLD,))
        self.assertEqual(live["unmeasuredChains"], [1, 4663])
        self.assertEqual(len(live["history"]), 1)
        self.assertEqual([c["chainId"] for c in live["chains"]], [8453])
        self.assertGreater(live["accruedUSD"], 0)

    def test_history_from_another_stake_is_ignored(self):
        old_point = {"asOf": NOW - DAY, "chains": [8453], "gauges": {f"8453:{G_CL}": {"fees": {WETH: 0.0}, "incentives": {}}}}
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        with mock.patch.object(pe, "token_meta", return_value=META[8453]):
            mine = pe.build_live([(FakeReader(base_answers(), logs=[]), pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf},
                                 1_000_000 * E18, 0.8, 600_000.0, prev_live={"stakeId": 1584, "history": [old_point]}, now_ts=NOW)
            other = pe.build_live([(FakeReader(base_answers(), logs=[]), pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf},
                                  1_000_000 * E18, 0.8, 600_000.0, prev_live={"stakeId": 999, "history": [old_point]}, now_ts=NOW)
        self.assertIsNotNone(mine["trailing"]["24h"])
        self.assertEqual(len(mine["history"]), 2)
        self.assertIsNone(other["trailing"]["24h"])
        self.assertEqual(len(other["history"]), 1)


class ChainReaderTest(unittest.TestCase):
    """Multicall3 encode/decode, empty targets skipped, 429 retried."""

    def _w3(self, responder, fail_first=0):
        real = Web3()
        calls = {"n": 0}

        def aggregate3(req):
            def call(block_identifier=None):
                calls["n"] += 1
                if calls["n"] <= fail_first:
                    raise Exception("429 Client Error: Too Many Requests")
                return [(True, responder(c["target"].lower(), bytes(c["callData"]))) for c in req]
            return mock.Mock(call=call)
        mc = mock.Mock()
        mc.functions.aggregate3.side_effect = aggregate3
        w3 = mock.Mock(codec=real.codec, to_checksum_address=Web3.to_checksum_address)
        w3.eth.get_block.return_value = {"timestamp": NOW}
        w3.eth.contract.return_value = mc
        return w3, calls

    def test_many_encodes_decodes_and_skips_empty_targets(self):
        codec = Web3().codec

        def responder(target, data):
            sel = data[:4]
            if sel == keccak(text="earnedFees(uint256,uint256)")[:4]:
                tid, mx = codec.decode(["uint256", "uint256"], data[4:])
                return codec.encode(["uint256", "uint256"], [tid * 10, mx])
            if sel == keccak(text="allocatedGauges(uint256)")[:4]:
                return codec.encode(["address[]"], [[Web3.to_checksum_address(G_CL)]])
            return b""
        w3, _ = self._w3(responder)
        r = pe.ChainReader(w3, 8453, block=123)
        out = r.many([(VRM_CL, "earnedFees(uint256,uint256)", [1584, 10_000], ["uint256", "uint256"]),
                      ("", "pool()", [], ["address"]),
                      (LV, "allocatedGauges(uint256)", [1584], ["address[]"]),
                      (G_CL, "pool()", [], ["address"])])
        self.assertEqual(out[0], (15840, 10_000))
        self.assertIsNone(out[1])                              # no target -> not called
        self.assertEqual([a.lower() for a in out[2]], [G_CL])
        self.assertIsNone(out[3])                              # empty return data -> None
        self.assertEqual((r.block, r.block_ts), (123, NOW))

    def test_rate_limit_is_retried(self):
        w3, calls = self._w3(lambda t, d: Web3().codec.encode(["uint256"], [7]), fail_first=2)
        with mock.patch.object(pe.time, "sleep") as sl:
            out = pe.ChainReader(w3, 8453, block=1).many([(VRM_CL, "incentiveCount()", [], ["uint256"])])
        self.assertEqual(out, [7])
        self.assertEqual(sl.call_count, 2)


if __name__ == "__main__":
    unittest.main()
