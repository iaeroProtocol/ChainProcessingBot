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
        self.assertEqual([c["chainId"] for c in live["chains"]], [8453])
        self.assertGreater(live["accruedUSD"], 0)


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
