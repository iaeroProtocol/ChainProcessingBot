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

    def call_one(self, target, sig, args, out_types, gas=300_000):
        return self.many([(target, sig, args, out_types)])[0]

    def logs(self, addresses, topics, from_block, to_block=None, step=10_000):
        """addresses None: any contract (the discovery scan), recorded as None."""
        self.log_calls.append((None if addresses is None else sorted(a.lower() for a in addresses), topics, from_block))
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
        # one filter, any contract (discovery; review 8 M-2), both claim events, indexed tokenId
        addrs, topics, _ = r.log_calls[0]
        self.assertEqual((addrs, len(r.log_calls)), (None, 1))
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

    def test_failed_reads_are_reported(self):
        a = base_answers()
        del a[(VRM_V2, "earnedFees(uint256,uint256)", (1584, 10_000))]
        del a[(VRM_V2, "earnedFees(uint256,uint256)", (1584, 20_000))]        # v2 fees unknown
        ch = pe.read_chain_position(FakeReader(a, logs=[]), 1584, registry=pe.FACTORY_REGISTRY_BASE, extra_gauges=(G_OLD,))
        self.assertEqual(sorted(ch["unreadGauges"]), sorted([G_OLD, G_V2]))   # G_OLD: no VRM; G_V2: fees failed
        self.assertTrue(ch["gaugeListRead"])
        self.assertEqual([g["readOk"] for g in ch["gauges"]], [True, False])
        # only the 2x-checkpoint read answered: it is used (it was read as 0 before)
        del a[(VRM_CL, "earnedFees(uint256,uint256)", (1584, 10_000))]
        cl = pe.read_chain_position(FakeReader(a, logs=[]), 1584, registry=pe.FACTORY_REGISTRY_BASE)["gauges"][0]
        self.assertEqual((cl["fees"][USDC], cl["readOk"]), (30 * 10**6, True))
        # a failed incentive read
        a = base_answers()
        del a[(VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 2, 10_000))]
        del a[(VRM_V2, "earnedIncentives(uint256,uint256,uint256)", (1584, 2, 20_000))]
        ch = pe.read_chain_position(FakeReader(a, logs=[]), 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertEqual(ch["unreadGauges"], [G_V2])
        # allocatedGauges itself failed
        del a[(LV, "allocatedGauges(uint256)", (1584,))]
        self.assertFalse(pe.read_chain_position(FakeReader(a, logs=[]), 1584)["gaugeListRead"])

    def test_no_gauges_means_claims_complete(self):
        a = {(LV, "allocatedGauges(uint256)", (1584,)): [], (LV, "tokenStates(uint256)", (1584,)): (pe.ZERO, T0, False, 0)}
        r = FakeReader(a, logs=[])
        ch = pe.read_chain_position(r, 1584)
        # no gauge: still one address-less scan (a claim would reveal a gauge to read; review 8 M-2)
        self.assertEqual((ch["claimsScanned"], ch["gaugeListRead"], ch["gauges"]), (True, True, []))
        self.assertEqual([c[0] for c in r.log_calls], [None])

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
        self.assertEqual(live["unmeasuredChains"], [])          # Robinhood is measured now (its own RPC)
        self.assertTrue(live["readComplete"])
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
        return {"asOf": self.NOW - ago, "chains": [8453], "accruedUSD": 0, "feesCumUSD": 0, "gauges": g,
                "complete": True}           # review 8 M-1: only complete points end a window

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
        # rewritten (measured headline): points stay >= 12 h apart whatever the run cadence; the newest is replaced
        # while it is under 12 h newer than the point before it (not while it is under 12 h old: hourly runs would
        # then keep replacing it and never build a 7-day window)
        hist = [self.point(d * DAY, d, 0) for d in range(14, 0, -1)] + [self.point(3 * 3600, 0.5, 0)]
        live = _live([_g2(G_CL, fees={USDC: 1 * 10**6})], self.NOW, hist)
        ages = [self.NOW - h["asOf"] for h in live["history"]]
        self.assertEqual(ages[-1], 0)                                   # current run appended
        self.assertIn(3 * 3600, ages)                                   # 21 h after its predecessor: kept
        self.assertTrue(all(a <= 10.5 * DAY for a in ages))
        self.assertLessEqual(len(ages), pe.HISTORY_MAX_POINTS)
        # hourly runs: the newest point moves until it is 12 h past the one before it, then a new one starts
        hist = [self.point(DAY, 1, 0)]
        asofs = []
        for h in range(0, 30):
            now = self.NOW + h * 3600
            live = pe.value_live([_chain(8453, T0, now, 1, [_g2(G_CL, fees={USDC: 10**6})])], META, PRICES, 1584,
                                 E18, 0.8, 600_000.0, now_ts=now, prev_history=hist)
            hist = live["history"]
        asofs = [h["asOf"] - self.NOW for h in hist]
        self.assertEqual(asofs, [-DAY, 0, 12 * 3600, 24 * 3600, 29 * 3600])
        self.assertTrue(all(b - a >= 12 * 3600 for a, b in zip(asofs[:-2], asofs[1:-1])))

    def test_first_point_of_an_epoch_is_kept(self):
        e = (self.NOW // pe.EPOCH_SEC + 1) * pe.EPOCH_SEC                # the next Thursday 00:00 UTC
        hist = [self.point(self.NOW - (e - 8 * 3600), 1, 0), self.point(self.NOW - (e - 4 * 3600), 1, 0)]
        for now in (e + 600, e + 3600, e + 7200):                       # hourly runs across the boundary
            live = pe.value_live([_chain(8453, T0, now, 1, [_g2(G_CL, fees={USDC: 10**6})])], META, PRICES, 1584,
                                 E18, 0.8, 600_000.0, now_ts=now, prev_history=hist)
            hist = live["history"]
        self.assertEqual([h["asOf"] - e for h in hist], [-8 * 3600, e + 600 - e, 7200])   # the 20:00 point gave way

    def test_partial_chain_coverage_is_excluded_and_flagged(self):
        eth = _chain(1, T0, self.NOW, 1, [_g2("0x" + "dd" * 20, fees={USDC: 10 * 10**6})])
        hist = [self.point(DAY, 90, 0)]                                  # Ethereum wasn't measured yesterday
        live = _live([_g2(G_CL, fees={USDC: 100 * 10**6})], self.NOW, hist, chains_extra=[eth])
        self.assertTrue(live["trailing"]["24h"]["partial"])
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 10.0)   # Base only
        self.assertIn(f"1:{'0x' + 'dd' * 20}", live["history"][-1]["gauges"])

    def _chain_at(self, now, gauges, cid=8453, claims=True, last_alloc=T0, unread=(), gauge_list=True):
        c = _chain(cid, T0, now, 1, gauges)
        c.update(claimsScanned=claims, lastAllocated=last_alloc, unreadGauges=list(unread), gaugeListRead=gauge_list)
        return c

    def _value(self, chains, now, history=None):
        return pe.value_live(chains, META, PRICES, 1584, 1_000_000 * E18, 0.8, 600_000.0, now_ts=now, prev_history=history)

    def test_run_without_claims_records_no_point(self):
        hist = [self.point(DAY, 90, 0)]
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL, fees={USDC: 5 * 10**6})], claims=False)], self.NOW, hist)
        self.assertEqual(live["history"], hist)                      # newest point kept, nothing appended
        self.assertIsNone(live["trailing"]["24h"])                   # no chain with claims at both ends
        # 3 h after a good point: a run without claims does not replace it
        recent = [self.point(3 * 3600, 90, 0)]
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL)], claims=False)], self.NOW, recent)
        self.assertEqual(live["history"], recent)
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL)], gauge_list=False)], self.NOW, recent)
        self.assertEqual(live["history"], recent)

    def test_chain_without_claims_is_left_out_of_the_point(self):
        G_E = "0x" + "dd" * 20
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL, fees={USDC: 5 * 10**6})]),
                            self._chain_at(self.NOW, [_g2(G_E, fees={"0xusdt": 7 * 10**6})], cid=1, claims=False)], self.NOW)
        (pt,) = live["history"]
        self.assertEqual((pt["chains"], list(pt["gauges"])), ([8453], [f"8453:{G_CL}"]))
        self.assertAlmostEqual(live["accruedUSD"], 12.0)             # the since-allocation figures still count it

    def test_unread_gauge_is_not_recorded_and_not_counted_later(self):
        bad = _g2(G_V2, fees={USDC: 1 * 10**6})
        bad["readOk"] = False
        day9 = self._value([self._chain_at(self.NOW - DAY, [_g2(G_CL, fees={USDC: 10 * 10**6}), bad],
                                           unread=[G_V2])], self.NOW - DAY)
        (pt,) = day9["history"]
        self.assertEqual((list(pt["gauges"]), pt["unread"]), ([f"8453:{G_CL}"], [f"8453:{G_V2}"]))
        # today both read in full, and the stake re-voted after yesterday's point: G_V2 still isn't "new"
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL, fees={USDC: 20 * 10**6}), _g2(G_V2, fees={USDC: 500 * 10**6})],
                                           last_alloc=self.NOW - 3600)], self.NOW, day9["history"])
        # adapted (review 8 M-1): a point with an unread gauge never ends a window (it was a partial window before)
        self.assertIsNone(live["trailing"]["24h"])
        self.assertIsNone(live["gauges"][1]["usdPerDay24h"])

    def test_gauge_missing_from_snapshot_counts_only_after_a_reallocation(self):
        G2 = "0x" + "a9" * 20
        hist = [self.point(DAY, 90, 0)]                              # G2 not in yesterday's point
        gauges = [_g2(G_CL, fees={USDC: 100 * 10**6}), _g2(G2, fees={USDC: 30 * 10**6})]
        # no re-vote since yesterday: G2 should have been there -> left out, partial
        live = self._value([self._chain_at(self.NOW, gauges, last_alloc=self.NOW - 3 * DAY)], self.NOW, hist)
        self.assertTrue(live["trailing"]["24h"]["partial"])
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 10.0)
        # re-voted onto G2 after yesterday's point: it is new, and all of it was earned since
        live = self._value([self._chain_at(self.NOW, gauges, last_alloc=self.NOW - 6 * 3600)], self.NOW, hist)
        self.assertFalse(live["trailing"]["24h"]["partial"])
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 40.0)

    def test_gauge_missing_now_flags_partial(self):
        G2 = "0x" + "a9" * 20
        hist = [self.point(DAY, 90, 0, extra={f"8453:{G2}": {"fees": {USDC: 5.0}, "incentives": {}}})]
        live = self._value([self._chain_at(self.NOW, [_g2(G_CL, fees={USDC: 100 * 10**6})])], self.NOW, hist)
        self.assertTrue(live["trailing"]["24h"]["partial"])
        self.assertAlmostEqual(live["trailing"]["24h"]["usdPerDay"], 10.0)

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
             mock.patch.object(pe, "FIRST_ALLOCATION_GAUGES", {}), \
             mock.patch.object(pe, "token_meta", return_value=META[8453]):
            live = pe.build_live([(good, pe.FACTORY_REGISTRY_BASE), (bad, None)], 1584, {8453: pf}, 1000 * E18, 0.8, 600.0,
                                 prev_live={"stakeId": 1584, "gauges": [{"chainId": 8453, "gauge": G_OLD}]}, now_ts=NOW)
            self.assertEqual(rcp.call_args_list[0].kwargs["extra_gauges"], (G_OLD,))
        self.assertEqual(live["unmeasuredChains"], [1])
        self.assertFalse(live["readComplete"])
        self.assertEqual(len(live["history"]), 1)
        self.assertEqual([c["chainId"] for c in live["chains"]], [8453])
        self.assertGreater(live["accruedUSD"], 0)

    def test_history_from_another_stake_is_ignored(self):
        old_point = {"asOf": NOW - DAY, "chains": [8453], "gauges": {f"8453:{G_CL}": {"fees": {WETH: 0.0}, "incentives": {}}},
                     "complete": True}
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        with mock.patch.object(pe, "token_meta", return_value=META[8453]), \
             mock.patch.object(pe, "FIRST_ALLOCATION_GAUGES", {}):
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

    def test_call_one_is_a_single_gas_capped_call(self):
        w3, _ = self._w3(lambda t, d: b"")
        codec = Web3().codec
        w3.eth.call.return_value = codec.encode(["address"], [Web3.to_checksum_address(G_CL)])
        r = pe.ChainReader(w3, 8453, block=77)
        self.assertEqual(r.call_one(VRM_CL, "gauge()", [], ["address"], gas=300_000).lower(), G_CL)
        tx, = w3.eth.call.call_args.args
        self.assertEqual((tx["gas"], tx["to"].lower(), bytes(tx["data"]), w3.eth.call.call_args.kwargs),
                         (300_000, VRM_CL, keccak(text="gauge()")[:4], {"block_identifier": 77}))
        w3.eth.call.side_effect = ValueError("out of gas")
        with self.assertRaises(ValueError):
            r.call_one(VRM_CL, "gauge()", [], ["address"])

    def test_rate_limit_is_retried(self):
        w3, calls = self._w3(lambda t, d: Web3().codec.encode(["uint256"], [7]), fail_first=2)
        with mock.patch.object(pe.time, "sleep") as sl:
            out = pe.ChainReader(w3, 8453, block=1).many([(VRM_CL, "incentiveCount()", [], ["uint256"])])
        self.assertEqual(out, [7])
        self.assertEqual(sl.call_count, 2)



class BlockLogsReader(FakeReader):
    """FakeReader whose claim logs carry block numbers: logs() returns those in [from_block, its pinned block]."""

    def __init__(self, answers, block_logs, block=1000, since_block=10):
        super().__init__(answers, logs=[], block=block)
        self.block_logs, self.since_block = block_logs, since_block
        self.fail = False
        self.need_address = False           # True: refuses address-less filters (publicnode on Ethereum)

    def block_at(self, ts):
        return self.since_block

    def logs(self, addresses, topics, from_block, to_block=None, step=10_000):
        self.log_calls.append((None if addresses is None else sorted(a.lower() for a in addresses), topics, from_block,
                               to_block))
        if self.fail or (addresses is None and self.need_address):
            return None
        want = None if addresses is None else {a.lower() for a in addresses}
        tb = self.block if to_block is None else min(to_block, self.block)
        return [dict(lg, blockNumber=b) for b, lg in self.block_logs
                if from_block <= b <= tb and (want is None or lg["address"].lower() in want)]


FEE_USDC = lambda amt: _log(VRM_V2, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), amt)
INC_AERO = lambda amt: _log(VRM_V2, pe.CLAIM_INCENTIVES_TOPIC, (1).to_bytes(32, "big"), amt)


class IncrementalClaimsTest(unittest.TestCase):
    """Claims are scanned from the last scanned block on (claimsState per chain, data/live_state.json); the scan is
    address-less where the RPC allows it (discovery, review 8 M-2), else per known VRM."""
    TOPICS = [[pe.CLAIM_FEES_TOPIC, pe.CLAIM_INCENTIVES_TOPIC], "0x" + (1584).to_bytes(32, "big").hex()]

    def read(self, reader, state):
        return pe.read_chain_position(reader, 1584, registry=pe.FACTORY_REGISTRY_BASE, claims_state=state)

    SEEN = {G_CL: {"firstSeen": NOW - 3600, "firstActive": True}, G_V2: {"firstSeen": NOW - 3600, "firstActive": True}}

    def state(self, block=900, v2_fees=None, cl=True):
        vrms = {VRM_V2: {"fees": dict(v2_fees or {USDC: 2 * 10**6}), "incentives": {AERO: 4 * E18}}}
        if cl:
            vrms[VRM_CL] = {"fees": {}, "incentives": {}}
        return {"since": T0, "sinceBlock": 10, "block": block, "blockTimestamp": NOW - 3600, "anyFrom": 10,
                "gauges": dict(self.SEEN), "unverified": {}, "vrms": vrms}

    def test_first_run_scans_from_the_allocation_and_records_every_vrm(self):
        r = BlockLogsReader(base_answers(), [(500, FEE_USDC(2 * 10**6)), (600, INC_AERO(4 * E18))])
        ch = self.read(r, None)
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 10)])      # once, from block_at(since)
        seen = {"firstSeen": NOW, "firstActive": True}
        self.assertEqual(ch["claimsState"], {"since": T0, "sinceBlock": 10, "block": 1000, "blockTimestamp": NOW,
                                             "anyFrom": 10, "gauges": {G_CL: seen, G_V2: seen}, "unverified": {}, "vrms": {
            VRM_V2: {"fees": {USDC: 2 * 10**6}, "incentives": {AERO: 4 * E18}},
            VRM_CL: {"fees": {}, "incentives": {}}}})                   # scanned, no claims: not rescanned later
        self.assertEqual(ch["gauges"][1]["claimed"], {USDC: 2 * 10**6, AERO: 4 * E18})

    def test_resume_scans_only_new_blocks_and_adds_to_the_totals(self):
        state = self.state()
        r = BlockLogsReader(base_answers(), [(500, FEE_USDC(2 * 10**6)), (600, INC_AERO(4 * E18)),
                                            (950, FEE_USDC(1 * 10**6))])
        ch = self.read(r, state)
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 901)])
        self.assertEqual(ch["gauges"][1]["claimedFees"], {USDC: 3 * 10**6})       # 2 before + 1 new, not 2 + 2 + 1
        self.assertEqual(ch["claimsState"]["vrms"][VRM_V2]["fees"], {USDC: 3 * 10**6})
        self.assertEqual(ch["claimsState"]["block"], 1000)
        self.assertEqual(state["block"], 900)                                    # the input is not mutated
        # same block again: nothing to scan, nothing added
        r2 = BlockLogsReader(base_answers(), [(950, FEE_USDC(1 * 10**6))])
        ch2 = self.read(r2, ch["claimsState"])
        self.assertEqual((r2.log_calls, ch2["claimsScanned"], ch2["gauges"][1]["claimedFees"]), ([], True, {USDC: 3 * 10**6}))

    def test_rpc_wanting_an_address_scans_the_known_vrms(self):
        # e.g. publicnode on Ethereum refuses address-less filters: per-VRM scans, no discovery
        r = BlockLogsReader(base_answers(), [(500, FEE_USDC(2 * 10**6)), (950, FEE_USDC(1 * 10**6))])
        r.need_address = True
        ch = self.read(r, self.state())
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 901), (sorted([VRM_CL, VRM_V2]), 901)])
        self.assertEqual((ch["claimsScanned"], ch["gauges"][1]["claimedFees"]), (True, {USDC: 3 * 10**6}))
        r = BlockLogsReader(base_answers(), [(500, FEE_USDC(2 * 10**6))])
        r.need_address = True
        ch = self.read(r, None)
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 10), (sorted([VRM_CL, VRM_V2]), 10)])
        self.assertEqual(ch["gauges"][1]["claimedFees"], {USDC: 2 * 10**6})

    def test_failed_scan_keeps_the_state_for_the_next_run(self):
        state = self.state(cl=True)
        r = BlockLogsReader(base_answers(), [(950, FEE_USDC(1 * 10**6))])
        r.fail = True
        ch = self.read(r, state)
        self.assertFalse(ch["claimsScanned"])
        self.assertEqual(ch["claimsState"], state)                     # retried from block 901 next run
        r.fail = False
        ch = self.read(r, ch["claimsState"])
        self.assertEqual((r.log_calls[-1][2], ch["claimsScanned"]), (901, True))
        self.assertEqual(ch["claimsState"]["vrms"][VRM_V2]["fees"], {USDC: 3 * 10**6})

    def test_restart_without_state_or_with_another_since_rescans_everything(self):
        logs = [(500, FEE_USDC(2 * 10**6)), (950, FEE_USDC(1 * 10**6))]
        for state in (None, {}, {"since": T0 - 1, "block": 900, "vrms": {VRM_V2: {"fees": {USDC: 99}, "incentives": {}}}},
                      {"since": T0, "block": "900", "vrms": {}}):
            r = BlockLogsReader(base_answers(), logs)
            ch = self.read(r, state)
            self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 10)], state)
            self.assertEqual(ch["claimsState"]["vrms"][VRM_V2]["fees"], {USDC: 3 * 10**6})

    def test_a_new_vrm_is_rescanned_only_where_address_less_scans_did_not_cover_it(self):
        cl_fee = _log(VRM_CL, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 5 * 10**6)
        cl_fee2 = _log(VRM_CL, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 1 * 10**6)
        logs = [(500, FEE_USDC(2 * 10**6)), (300, cl_fee), (990, cl_fee2)]

        def run(any_from, logs=logs):
            state = self.state(cl=False)
            state["vrms"][VRM_V2] = {"fees": {USDC: 2 * 10**6}, "incentives": {}}
            state["anyFrom"] = any_from
            r = BlockLogsReader(base_answers(), logs)
            return r, self.read(r, state)
        # no address-less coverage on record (per-VRM scans so far): from block_at(since) up to 900
        r, ch = run(None)
        self.assertEqual([(c[0], c[2], c[3]) for c in r.log_calls], [(None, 901, None), ([VRM_CL], 10, 900)])
        self.assertEqual(ch["gauges"][0]["claimedFees"], {USDC: 6 * 10**6})       # 5 (block 300) + 1 (block 990)
        self.assertEqual(ch["gauges"][1]["claimedFees"], {USDC: 2 * 10**6})
        self.assertEqual(ch["claimsState"]["anyFrom"], 901)                      # covered from here on
        # address-less scans since block 400: only the range before it (review 9 L-3)
        r, ch = run(400)
        self.assertEqual([(c[0], c[2], c[3]) for c in r.log_calls], [(None, 901, None), ([VRM_CL], 10, 399)])
        self.assertEqual(ch["gauges"][0]["claimedFees"], {USDC: 6 * 10**6})
        # covered since the first allocation: no rescan at all (any claim before would have been seen)
        r, ch = run(10, logs=[(500, FEE_USDC(2 * 10**6)), (990, cl_fee2)])
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 901)])
        self.assertEqual(ch["gauges"][0]["claimedFees"], {USDC: 1 * 10**6})
        self.assertEqual(ch["claimsState"]["anyFrom"], 10)

    def test_per_vrm_fallback_breaks_the_coverage(self):
        r = BlockLogsReader(base_answers(), [(950, FEE_USDC(1 * 10**6))])
        r.need_address = True
        ch = self.read(r, self.state())
        self.assertIsNone(ch["claimsState"]["anyFrom"])

    def test_rpc_behind_the_state_means_claims_unknown(self):
        state = self.state(block=2000)
        r = BlockLogsReader(base_answers(), [], block=1000)
        ch = self.read(r, state)
        self.assertEqual((ch["claimsScanned"], ch["claimsState"], r.log_calls), (False, state, []))

    def test_unresolved_incentive_claim_is_retried_not_lost(self):
        unknown = _log(VRM_V2, pe.CLAIM_INCENTIVES_TOPIC, (9).to_bytes(32, "big"), 4 * E18)   # program 9: unreadable
        r = BlockLogsReader(base_answers(), [(500, FEE_USDC(2 * 10**6)), (600, unknown)])
        ch = self.read(r, None)
        self.assertFalse(ch["claimsScanned"])
        seen = {"firstSeen": NOW, "firstActive": True}
        self.assertEqual(ch["claimsState"], {"gauges": {G_CL: seen, G_V2: seen}, "unverified": {}})  # no block: rescan
        self.assertEqual(ch["gauges"][1]["claimed"], {})


def _registered(a, gauge, vrm, registered=True, with_registry=True):
    """answers making `vrm` the VRM of `gauge`, registered (or not) with the LeafVoter."""
    a[(vrm, "gauge()", ())] = gauge
    a[(gauge, "votingRewardsManager()", ())] = vrm
    if with_registry:
        a[(REG, "gaugeToRewards(address)", (gauge,))] = vrm
    a[(LV, "gaugeStates(address)", (gauge,))] = (0, 0, 0, registered, registered, 0, 0, 0, 0, 0, 0, 0)
    a[(vrm, "token0()", ())], a[(vrm, "token1()", ())] = USDC, WETH
    a[(vrm, "earnedFees(uint256,uint256)", (1584, 10_000))] = (7 * 10**6, 0)
    a[(vrm, "earnedFees(uint256,uint256)", (1584, 20_000))] = (7 * 10**6, 0)
    a[(vrm, "incentiveCount()", ())] = 0
    return a


class GaugeDiscoveryTest(unittest.TestCase):
    """Review 8 M-2: gauges the stake left before the bot first ran, or between two runs, are still measured."""

    def test_first_allocation_gauges_from_config(self):
        cfg = pe.FIRST_ALLOCATION_GAUGES[1584]
        self.assertEqual({c: len(g) for c, g in cfg.items()}, {8453: 9, 1: 1, 4663: 1})
        for gs in cfg.values():
            self.assertTrue(all(Web3.to_checksum_address(g) == g for g in gs))           # checksummed forms
        self.assertIn("0xe033F4Bd3D7Ccf537A2F954eCDC8eB1218e3B7a6", cfg[4663])
        # build_live reads them on their chain even when allocatedGauges no longer lists them
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        with mock.patch.object(pe, "read_chain_position", wraps=pe.read_chain_position) as rcp, \
             mock.patch.object(pe, "token_meta", return_value=META[8453]):
            pe.build_live([(BlockLogsReader(base_answers(), []), pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf},
                          1000 * E18, 0.8, 600.0, now_ts=NOW)
        self.assertEqual(rcp.call_args.kwargs["extra_gauges"], tuple(cfg[8453]))

    def test_a_claim_from_a_registered_gauge_not_read_adds_it(self):
        a = _registered(base_answers(), G_OLD, VRM_OLD)
        old_fee = _log(VRM_OLD, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 3 * 10**6)
        r = BlockLogsReader(a, [(700, old_fee)])
        ch = pe.read_chain_position(r, 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertEqual(ch["discoveredGauges"], [G_OLD])
        old = [g for g in ch["gauges"] if g["gauge"] == G_OLD][0]
        self.assertEqual((old["active"], old["fees"], old["claimedFees"]), (False, {USDC: 7 * 10**6, WETH: 0},
                                                                           {USDC: 3 * 10**6}))
        self.assertIn(G_OLD, ch["claimsState"]["gauges"])                    # remembered from now on
        self.assertTrue(ch["claimsScanned"])
        # next run: the state's gauges are read even though nothing else lists G_OLD
        r2 = BlockLogsReader(a, [(700, old_fee)], block=1100)
        ch2 = pe.read_chain_position(r2, 1584, registry=pe.FACTORY_REGISTRY_BASE, claims_state=ch["claimsState"])
        self.assertIn(G_OLD, [g["gauge"] for g in ch2["gauges"]])
        self.assertEqual(ch2["discoveredGauges"], [])
        # Ethereum / Robinhood (no registry): the gauge's own pointer
        a = _registered(base_answers(), G_OLD, VRM_OLD, with_registry=False)
        ch = pe.read_chain_position(BlockLogsReader(a, [(700, old_fee)]), 1584)
        self.assertEqual(ch["discoveredGauges"], [G_OLD])

    def test_claims_from_anything_else_are_ignored(self):
        fake_vrm, fake_gauge = "0x" + "e1" * 20, "0x" + "e2" * 20
        spoof = _log(fake_vrm, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 10**12)
        for variant in ("unregistered", "vrm mismatch", "no gauge()"):
            a = _registered(base_answers(), fake_gauge, fake_vrm, registered=variant != "unregistered")
            if variant == "vrm mismatch":
                a[(REG, "gaugeToRewards(address)", (fake_gauge,))] = VRM_CL
            if variant == "no gauge()":
                del a[(fake_vrm, "gauge()", ())]
            ch = pe.read_chain_position(BlockLogsReader(a, [(700, spoof)]), 1584, registry=pe.FACTORY_REGISTRY_BASE)
            self.assertEqual(ch["discoveredGauges"], [], variant)
            self.assertNotIn(fake_gauge, [g["gauge"] for g in ch["gauges"]], variant)
            self.assertNotIn(fake_vrm, ch["claimsState"]["vrms"], variant)
            self.assertTrue(ch["claimsScanned"], variant)                    # never a reason to stall the feed

    def test_emitters_are_checked_one_by_one_and_never_fail_the_read(self):
        # review 9 L-1: a contract whose gauge() burns all gas (or reverts) is rejected in its own gas-capped call;
        # it never joins a batch, never fails the chain's read, and is never checked again
        spoof = "0x" + "e1" * 20
        calls = []

        class R(BlockLogsReader):
            def many(self, cs):
                assert not any(sig == "gauge()" for _, sig, _, _ in cs), "an emitter's gauge() inside a batch"
                return super().many(cs)

            def call_one(self, target, sig, args, out_types, gas=0):
                calls.append((target, sig, gas))
                if target == spoof:
                    raise ValueError("{'code': -32003, 'message': 'out of gas'}")
                return super().call_one(target, sig, args, out_types)
        log = (700, _log(spoof, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 10**12))
        ch = pe.read_chain_position(R(base_answers(), [log]), 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertTrue(ch["claimsScanned"])
        self.assertEqual(calls, [(spoof, "gauge()", pe.VERIFY_GAS)])
        self.assertEqual(ch["claimsState"]["unverified"], {spoof: {"from": 700, "status": "rejected"}})
        calls.clear()
        ch2 = pe.read_chain_position(R(base_answers(), [log], block=1100), 1584, registry=pe.FACTORY_REGISTRY_BASE,
                                     claims_state=ch["claimsState"])
        self.assertEqual((calls, ch2["claimsScanned"]), ([], True))               # not checked again

    def test_at_most_50_checks_a_run_the_rest_wait(self):
        spoofs = ["0x" + format(0xe0000 + i, "040x") for i in range(60)]
        logs = [(600 + i, _log(v, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 1)) for i, v in enumerate(spoofs)]
        n = []

        class R(BlockLogsReader):
            def call_one(self, target, sig, args, out_types, gas=0):
                n.append(target)
                return pe.ZERO                                            # not a VRM
        ch = pe.read_chain_position(R(base_answers(), logs), 1584, registry=pe.FACTORY_REGISTRY_BASE)
        st = ch["claimsState"]["unverified"]
        self.assertEqual((len(n), ch["claimsScanned"]), (pe.MAX_VERIFY_PER_RUN, True))
        self.assertEqual(sorted(u["status"] for u in st.values()).count("pending"), 10)
        n.clear()
        ch = pe.read_chain_position(R(base_answers(), logs, block=1100), 1584, registry=pe.FACTORY_REGISTRY_BASE,
                                    claims_state=ch["claimsState"])
        self.assertEqual(len(n), 10)                                      # only the 10 left
        self.assertTrue(all(u["status"] == "rejected" for u in ch["claimsState"]["unverified"].values()))

    def test_a_vrm_confirmed_later_is_rescanned_from_its_first_unchecked_claim(self):
        # the RPC failed on the check (transient): pending, its claims not counted; confirmed next run, its claims
        # since it was first seen are rescanned by address
        import requests
        a = _registered(base_answers(), G_OLD, VRM_OLD)
        f1 = _log(VRM_OLD, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 3 * 10**6)
        f2 = _log(VRM_OLD, pe.CLAIM_FEES_TOPIC, bytes(12) + bytes.fromhex(USDC[2:]), 2 * 10**6)
        down = [True]

        class R(BlockLogsReader):
            def call_one(self, target, sig, args, out_types, gas=0):
                if down[0]:
                    raise requests.exceptions.ConnectionError("connection reset")
                return super().call_one(target, sig, args, out_types)
        r = R(a, [(700, f1), (1050, f2)])
        ch = pe.read_chain_position(r, 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertEqual(ch["claimsState"]["unverified"], {VRM_OLD: {"from": 700, "status": "pending"}})
        self.assertNotIn(G_OLD, [g["gauge"] for g in ch["gauges"]])
        self.assertTrue(ch["claimsScanned"])
        down[0] = False
        r2 = R(a, [(700, f1), (1050, f2)], block=1100)
        ch2 = pe.read_chain_position(r2, 1584, registry=pe.FACTORY_REGISTRY_BASE, claims_state=ch["claimsState"])
        self.assertEqual(ch2["discoveredGauges"], [G_OLD])
        self.assertEqual([(c[0], c[2], c[3]) for c in r2.log_calls], [(None, 1001, None), ([VRM_OLD], 700, 1000)])
        old = [g for g in ch2["gauges"] if g["gauge"] == G_OLD][0]
        self.assertEqual(old["claimedFees"], {USDC: 5 * 10**6})                 # 3 (rescanned) + 2 (this run)
        self.assertEqual(ch2["claimsState"]["unverified"], {})

    def test_a_gauge_first_read_while_not_allocated_never_counts_from_zero(self):
        # a window whose older point lacks a gauge counts it from zero only if it was first seen after that point
        # while allocated (review 9 L-2): a gauge first read unallocated (found from a claim, or from config) may hold
        # earnings from before the window
        snap = {"asOf": NOW - DAY, "chains": [8453], "complete": True, "unread": [],
                "gauges": {f"8453:{G_CL}": {"fees": {USDC: 10.0}, "incentives": {}}}}
        cur = {"asOf": NOW, "chains": [8453], "gauges": {
            f"8453:{G_CL}": {"active": True, "fees": {USDC: 20.0}, "incentives": {}},
            f"8453:{G_OLD}": {"active": False, "firstSeen": NOW, "firstActive": False, "fees": {USDC: 500.0},
                              "incentives": {}}}}
        price = lambda cid, t: 1.0
        d = pe.window_delta(cur, snap, price, {8453: NOW - 3600})               # re-voted after the snapshot
        self.assertTrue(d["partial"])
        self.assertAlmostEqual(d["usdPerDay"], 10.0)                            # G_OLD's 500 left out
        # first seen after the snapshot while allocated (joined at a re-vote), left again since: counted from zero
        cur["gauges"][f"8453:{G_OLD}"].update(firstSeen=NOW - 3600, firstActive=True)
        d = pe.window_delta(cur, snap, price, {8453: NOW - 3600})
        self.assertFalse(d["partial"])
        self.assertAlmostEqual(d["usdPerDay"], 510.0)
        # first seen while allocated, but at (or before) the snapshot: it should have been in it -> partial
        cur["gauges"][f"8453:{G_OLD}"].update(firstSeen=NOW - DAY)
        self.assertTrue(pe.window_delta(cur, snap, price, {8453: NOW - 3600})["partial"])


class BlockAtTest(unittest.TestCase):
    """ChainReader.block_at: block times are never assumed (Robinhood: 0.1 s blocks; Base 2 s; Ethereum 12 s)."""

    def reader(self, block_time, head):
        genesis = 1_700_000_000
        ts_of = lambda n: genesis + int(n * block_time)
        w3 = mock.Mock(to_checksum_address=Web3.to_checksum_address)
        w3.eth.get_block.side_effect = lambda n: {"timestamp": ts_of(int(n))}
        r = pe.ChainReader(w3, 4663, block=head)
        return r, ts_of, w3

    def test_last_block_at_or_before(self):
        for bt, head in ((0.1, 60_000_000), (2.0, 37_000_000), (12.0, 23_000_000)):
            r, ts_of, w3 = self.reader(bt, head)
            for back in (0, 1, 3600, 86_400 + 7, 9 * 86_400 + 1):
                ts = r.block_ts - back
                w3.eth.get_block.reset_mock()
                b = r.block_at(ts)
                self.assertLessEqual(ts_of(b), ts, (bt, back))
                if back:
                    self.assertGreater(ts_of(b + 1), ts, (bt, back))      # the LAST block at or before ts
                else:
                    self.assertEqual(b, head)                             # never past the pinned block
                self.assertLess(w3.eth.get_block.call_count, 120)          # galloping + bisection, not a walk
            self.assertEqual(r.block_at(r.block_ts + 100), head)            # the future: the pinned block
            self.assertEqual(r.block_at(0), 0)


class LogsTest(unittest.TestCase):
    """ChainReader.logs: the range per call halves on errors (public RPCs cap it, e.g. 1000 blocks) and the whole
    range is covered exactly once; a range refused at min_step means claims unknown (None)."""

    def reader(self, cap):
        w3 = mock.Mock(to_checksum_address=Web3.to_checksum_address)
        w3.eth.get_block.return_value = {"timestamp": NOW}
        calls = []

        def get_logs(f):
            calls.append((f["fromBlock"], f["toBlock"]))
            if cap is None or f["toBlock"] - f["fromBlock"] + 1 > cap:
                raise ValueError("block range is too large")
            return [{"blockNumber": n} for n in range(f["fromBlock"], f["toBlock"] + 1) if n % 997 == 0]
        w3.eth.get_logs.side_effect = get_logs
        return pe.ChainReader(w3, 8453, block=100_000), calls

    def test_capped_rpc_is_covered_without_gaps(self):
        r, calls = self.reader(1000)
        out = r.logs([VRM_CL], [], 20_000)
        self.assertEqual([x["blockNumber"] for x in out], [n for n in range(20_000, 100_001) if n % 997 == 0])
        ok = sorted((a, b) for a, b in calls if b - a + 1 <= 1000)
        self.assertEqual(ok[0][0], 20_000)
        self.assertEqual(ok[-1][1], 100_000)
        self.assertTrue(all(b + 1 == c for (_, b), (c, _) in zip(ok, ok[1:])))

    def test_refused_at_min_step_is_none(self):
        r, _ = self.reader(None)
        self.assertIsNone(r.logs([VRM_CL], [], 20_000))


def _pt(asof, usdc, chains=(8453,), complete=True, unread=(), last_alloc=T0):
    return {"asOf": asof, "chains": list(chains), "complete": complete, "unread": list(unread),
            "lastAllocated": {str(c): last_alloc for c in chains},
            "gauges": {f"{c}:{G_CL}": {"fees": {USDC: usdc}, "incentives": {}} for c in chains}}


class EpochRateTest(unittest.TestCase):
    """yield_history: measured earnings between complete points within a few hours of an epoch's start and end."""
    E = 1792627200 + 7 * DAY
    price = staticmethod(lambda cid, t: 1.0 if t == USDC else 0.0)

    def test_points_near_both_ends(self):
        h = [_pt(self.E - 10 * 3600, 50), _pt(self.E + 2 * 3600, 100), _pt(self.E + 3 * DAY, 400),
             _pt(self.E + 7 * DAY + 2 * 3600, 800)]
        r = pe.epoch_rate(h, self.E, self.E + 7 * DAY, self.price)
        self.assertEqual((r["from"], r["to"], r["days"]), (self.E + 2 * 3600, self.E + 7 * DAY + 2 * 3600, 7.0))
        self.assertAlmostEqual(r["usdPerDay"], 100.0)

    def test_none_without_complete_points_near_the_boundaries(self):
        far = [_pt(self.E + 7 * 3600, 100), _pt(self.E + 7 * DAY + 2 * 3600, 800)]        # 7 h after the start
        self.assertIsNone(pe.epoch_rate(far, self.E, self.E + 7 * DAY, self.price))
        inc = [_pt(self.E + 3600, 100, complete=False), _pt(self.E + 7 * DAY + 3600, 800)]
        self.assertIsNone(pe.epoch_rate(inc, self.E, self.E + 7 * DAY, self.price))
        unread = [_pt(self.E + 3600, 100), _pt(self.E + 7 * DAY + 3600, 800, unread=["8453:x"])]
        self.assertIsNone(pe.epoch_rate(unread, self.E, self.E + 7 * DAY, self.price))
        # a chain measured at only one end: partial -> no entry
        part = [_pt(self.E + 3600, 100), _pt(self.E + 7 * DAY + 3600, 800, chains=(8453, 4663))]
        self.assertIsNone(pe.epoch_rate(part, self.E, self.E + 7 * DAY, self.price))
        self.assertIsNone(pe.epoch_rate([], self.E, self.E + 7 * DAY, self.price))


class BuildLiveChainsTest(unittest.TestCase):
    def test_unreachable_chain_is_unmeasured_and_prices_and_state_are_returned(self):
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        with mock.patch.object(pe, "token_meta", return_value=META[8453]), \
             mock.patch.object(pe, "FIRST_ALLOCATION_GAUGES", {}):
            live = pe.build_live([(BlockLogsReader(base_answers(), []), pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf},
                                 1000 * E18, 0.8, 600.0, now_ts=NOW, unreachable=[4663],
                                 claims_state={"stakeId": 1584, "chains": {"1": {"keep": True}}})
        self.assertEqual(live["unmeasuredChains"], [4663])
        self.assertFalse(live["readComplete"])
        self.assertEqual(live["_prices"][8453][USDC], 1.0)
        cs = live["_claimsState"]
        self.assertEqual((cs["stakeId"], sorted(cs["chains"])), (1584, ["1", "8453"]))    # other chains' state kept
        self.assertEqual(cs["chains"]["8453"]["block"], 1000)

    def test_claims_state_of_another_stake_is_ignored(self):
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0.0)} for t in toks}
        r = BlockLogsReader(base_answers(), [])
        with mock.patch.object(pe, "token_meta", return_value=META[8453]), \
             mock.patch.object(pe, "FIRST_ALLOCATION_GAUGES", {}):
            pe.build_live([(r, pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf}, 1000 * E18, 0.8, 600.0, now_ts=NOW,
                          claims_state={"stakeId": 77, "chains": {"8453": {"since": T0, "block": 999, "vrms": {
                              VRM_CL: {"fees": {}, "incentives": {}}, VRM_V2: {"fees": {}, "incentives": {}}}}}})
        self.assertEqual([(c[0], c[2]) for c in r.log_calls], [(None, 10)])     # full scan, not from 1000


if __name__ == "__main__":
    unittest.main()
