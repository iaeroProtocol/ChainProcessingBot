# test_realized_yield.py
# Unit tests for the realized-APY feed (data/estimated_rewards_usd.json + data/yield_history.json). No network.
# Run: python -m unittest discover -s tests
import copy
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from web3 import Web3  # noqa: E402

import realized_yield  # noqa: E402
from realized_yield import (  # noqa: E402
    DAY,
    WEEK,
    ZERO_ADDRESS,
    WETH_ADDRESS,
    build_estimated_rewards,
    compute_realized,
    dump_yield_history,
    epoch_start,
    is_sane_apy,
    last_completed_epoch,
    latest_funded_epoch,
    merge_yield_history,
    sanity_problems,
    select_epoch,
    trusted_dex_tokens,
)

E18 = 10 ** 18
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
AERO = realized_yield.AERO_ADDRESS.lower()
IAERO = realized_yield.IAERO_ADDRESS.lower()
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
OLD_AERO = "0x940181a94a35a4569e4529a3cdfb74e38fd98631"

EPOCH_22_OCT = 1792627200  # Thu 2026-10-22 00:00 UTC
EPOCH_15_OCT = EPOCH_22_OCT - WEEK

# every field TwitterBot / DefiLlama / the legacy keeper's file carried
LEGACY_KEYS = {
    "epochStart", "splitBps", "protocolWeeklyUSD_1e18", "pegWeeklyUSD_1e18",
    "estimatedWeeklyUSD_1e18", "estimatedWeeklyUSD_human", "stakersWeeklyUSD_1e18",
    "stakersWeeklyUSD_human", "estimatedAnnualUSD_1e18", "estimatedAnnualUSD_human",
    "totalStaked_1e18", "tvlUSD_1e18", "apyPct", "aeroPrice_1e18", "iaeroPrice_1e18",
    "iaeroAeroRatio_1e18", "usedFallbackPrice", "updatedAt", "source",
}


class EpochMathTest(unittest.TestCase):
    def test_epochs_start_thursday_00_utc(self):
        self.assertEqual(epoch_start(EPOCH_22_OCT + 61), EPOCH_22_OCT)  # funding tx at 00:01:01
        self.assertEqual(EPOCH_22_OCT % WEEK, 0)
        self.assertEqual(datetime.fromtimestamp(EPOCH_22_OCT, tz=timezone.utc).strftime("%A %H:%M"), "Thursday 00:00")

    def test_last_completed_epoch(self):
        # Thu 22 Oct 02:31 UTC (daily run): the 22 Oct epoch is still running -> 15 Oct
        self.assertEqual(last_completed_epoch(EPOCH_22_OCT + 2 * 3600 + 31 * 60), EPOCH_15_OCT)
        # exactly at the flip the previous week is complete
        self.assertEqual(last_completed_epoch(EPOCH_22_OCT), EPOCH_15_OCT)
        # one week later the 22 Oct epoch (final Aerodrome-era funding) is the one reported
        self.assertEqual(last_completed_epoch(EPOCH_22_OCT + WEEK + 1), EPOCH_22_OCT)

    def test_latest_funded_epoch(self):
        doc = {"epochs": {str(EPOCH_15_OCT): {"tokens": [USDC]}, str(EPOCH_22_OCT): {"tokens": [USDC]},
                          str(EPOCH_22_OCT + WEEK): {"tokens": []}}}
        # Thu 22 Oct 02:31, after the 00:01 funding landed -> the running 22 Oct epoch
        self.assertEqual(latest_funded_epoch(doc, EPOCH_22_OCT + 9060), EPOCH_22_OCT)
        # Thu 22 Oct before the funding was scanned -> previous week
        self.assertEqual(latest_funded_epoch({"epochs": {str(EPOCH_15_OCT): {"tokens": [USDC]}}}, EPOCH_22_OCT + 30), EPOCH_15_OCT)
        # an entry with no tokens is not funded; future keys are ignored
        self.assertEqual(latest_funded_epoch(doc, EPOCH_22_OCT + WEEK + 60), EPOCH_22_OCT)
        self.assertEqual(latest_funded_epoch(doc, EPOCH_15_OCT - 1), None)

    def test_select_epoch_modes_and_staleness(self):
        doc = {"epochs": {str(EPOCH_22_OCT): {"tokens": [USDC]}}}
        self.assertEqual(select_epoch(doc, EPOCH_22_OCT + 9060), (EPOCH_22_OCT, False))
        self.assertEqual(select_epoch(doc, EPOCH_22_OCT + 9060, "last_completed"), (EPOCH_15_OCT, False))
        # keeper missed 29 Oct and 5 Nov: still fine at 5 Nov 00:00 (exactly 2 weeks), stale after
        self.assertEqual(select_epoch(doc, EPOCH_22_OCT + 2 * WEEK), (EPOCH_22_OCT, False))
        self.assertEqual(select_epoch(doc, EPOCH_22_OCT + 2 * WEEK + 9060), (EPOCH_22_OCT, True))
        # nothing funded at all -> last completed (reports 0)
        self.assertEqual(select_epoch({"epochs": {}}, EPOCH_22_OCT + 9060), (EPOCH_15_OCT, False))

    def test_sanity_guard(self):
        self.assertTrue(is_sane_apy({"apyPct": 13.8}))
        self.assertTrue(is_sane_apy({"apyPct": 0.0}))
        self.assertTrue(is_sane_apy({"apyPct": 500.0}))
        self.assertFalse(is_sane_apy({"apyPct": 500.01}))
        self.assertFalse(is_sane_apy({"apyPct": float("nan")}))
        self.assertFalse(is_sane_apy({"apyPct": -1.0}))

    def test_unpriced_core_tokens_are_not_sane(self):
        funded = [{"address": USDC, "amount": 8_300 * 10**6, "decimals": 6, "priceUsd": 1.0}]
        ok = compute_realized(EPOCH_22_OCT, funded, 4_710_927 * E18, 4_710_930 * E18, 0.6656, 0.802)
        self.assertEqual(sanity_problems(ok), [])
        both = compute_realized(EPOCH_22_OCT, funded, 4_710_927 * E18, 4_710_930 * E18, 0.0, 0.0)
        self.assertEqual((both["apyPct"], both["tvlUSD_1e18"]), (0.0, "0"))     # what would have been published
        self.assertEqual(sanity_problems(both), ["AERO is unpriced", "iAERO is unpriced",
                                                 "stakedUSD is 0 with a non-zero stake", "tvlUSD is 0 with a non-zero stake"])
        self.assertFalse(is_sane_apy(both))
        st = 4_710_927 * E18
        self.assertEqual(sanity_problems(compute_realized(EPOCH_22_OCT, funded, st, st, 0.0, 0.802)), ["iAERO is unpriced"])
        self.assertEqual(sanity_problems(compute_realized(EPOCH_22_OCT, funded, st, st, 0.6656, 0.0)), ["AERO is unpriced"])
        # an empty stake is not a pricing failure
        self.assertEqual(sanity_problems(compute_realized(EPOCH_22_OCT, funded, 0, 0, 0.6656, 0.802)), [])


class ComputeRealizedTest(unittest.TestCase):
    def test_apy_is_weekly_return_times_52(self):
        funded = [
            {"address": USDC, "amount": 5_000 * 10**6, "decimals": 6, "priceUsd": 1.0},
            {"address": OLD_AERO, "amount": 2_500 * E18, "decimals": 18, "priceUsd": 0.8},
        ]  # $7,000
        p = compute_realized(EPOCH_15_OCT, funded, staked_at_start_raw=4_000_000 * E18,
                             total_staked_raw=4_100_000 * E18, iaero_price=0.7, aero_price=0.8,
                             distributor=DIST, now_ts=EPOCH_22_OCT + 9000)
        weekly = 7_000 / (4_000_000 * 0.7)
        self.assertAlmostEqual(p["weeklyYieldPct"], weekly * 100, places=9)
        self.assertAlmostEqual(p["apyPct"], weekly * 52 * 100, places=9)
        self.assertEqual(p["method"], "realized")
        self.assertEqual((p["epoch"], p["epochStart"], p["epochEnd"]), (EPOCH_15_OCT, EPOCH_15_OCT, EPOCH_22_OCT))
        self.assertEqual(p["fundedUSD_human"], "7000.0000")
        self.assertEqual(p["stakersWeeklyUSD_1e18"], str(7_000 * E18))
        self.assertEqual(p["estimatedWeeklyUSD_1e18"], str(8_750 * E18))        # 7000 / 80%
        self.assertEqual(p["protocolWeeklyUSD_1e18"], str(875 * E18))
        self.assertEqual(p["estimatedAnnualUSD_1e18"], str(8_750 * 52 * E18))
        self.assertEqual(p["stakedUSD_1e18"], str(2_800_000 * E18))
        # TVL keeps its legacy meaning: CURRENT totalStaked x iAERO price
        self.assertEqual(p["totalStaked_1e18"], str(4_100_000 * E18))
        self.assertEqual(p["tvlUSD_1e18"], str(2_870_000 * E18))
        self.assertEqual(p["iaeroAeroRatio_1e18"], str(875 * 10**15))
        self.assertFalse(p["usedFallbackPrice"])
        self.assertEqual(p["updatedAt"], "2026-10-22T02:30:00.000Z")

    def test_schema_keeps_every_legacy_field_and_type(self):
        p = compute_realized(EPOCH_15_OCT, [], 1, 1, 0.66, 0.81)
        self.assertTrue(LEGACY_KEYS.issubset(p.keys()), LEGACY_KEYS - set(p.keys()))
        self.assertIsInstance(p["apyPct"], float)                     # TwitterBot: typeof === 'number'
        self.assertIsInstance(p["tvlUSD_1e18"], str)                  # DefiLlama: Number(str) / 1e18
        int(p["tvlUSD_1e18"])
        self.assertEqual(json.loads(json.dumps(p)), p)                # JSON-serialisable as-is

    def test_unfunded_epoch_reports_zero_not_stale(self):
        p = compute_realized(EPOCH_15_OCT, [], 4_000_000 * E18, 4_000_000 * E18, 0.7, 0.8)
        self.assertEqual(p["apyPct"], 0.0)
        self.assertEqual(p["weeklyYieldPct"], 0.0)
        self.assertEqual(p["fundedTokenCount"], 0)
        self.assertEqual(p["epoch"], EPOCH_15_OCT)
        self.assertGreater(int(p["tvlUSD_1e18"]), 0)  # DefiLlama still gets a TVL

    def test_unpriced_tokens_are_excluded_and_listed(self):
        funded = [
            {"address": USDC, "amount": 1_000 * 10**6, "decimals": 6, "priceUsd": 1.0},
            {"address": "0xABCDEF0000000000000000000000000000000001", "amount": 5 * E18, "decimals": 18, "priceUsd": 0.0},
        ]
        p = compute_realized(EPOCH_15_OCT, funded, 1_000_000 * E18, 1_000_000 * E18, 1.0, 1.0)
        self.assertEqual(p["fundedUSD_human"], "1000.0000")
        self.assertEqual(p["unpricedTokens"], ["0xabcdef0000000000000000000000000000000001"])
        self.assertEqual(p["fundedTokenCount"], 2)

    def test_missing_iaero_price_falls_back_to_aero(self):
        p = compute_realized(EPOCH_15_OCT, [], 1_000 * E18, 1_000 * E18, 0.0, 0.8)
        self.assertTrue(p["usedFallbackPrice"])
        self.assertEqual(p["iaeroPrice_1e18"], p["aeroPrice_1e18"])

    def test_only_trusted_dex_prices_count(self):
        THIN = "0x" + "66" * 20
        funded = [{"address": USDC, "amount": 3_000 * 10**6, "decimals": 6, "priceUsd": 1.0, "source": "llama"},
                  {"address": AERO, "amount": 1_000 * E18, "decimals": 18, "priceUsd": 0.8, "source": "dex",
                   "dexDepthUsd": 6_000_000.0},                          # listed and deep: counts
                  {"address": OLD_AERO, "amount": 1_000 * E18, "decimals": 18, "priceUsd": 0.8, "source": "dex",
                   "dexDepthUsd": 6_000_000.0},                          # deep but not listed: left out
                  {"address": THIN, "amount": 100 * E18, "decimals": 18, "priceUsd": 2.0, "source": "dex",
                   "dexDepthUsd": 30_000.0},                             # neither: left out
                  {"address": "0x" + "77" * 20, "amount": E18, "decimals": 18, "priceUsd": 0.0, "source": "none"}]
        p = compute_realized(EPOCH_15_OCT, funded, 4_000_000 * E18, 4_000_000 * E18, 0.7, 0.8)
        self.assertEqual(p["fundedUSD_human"], "3800.0000")                  # USDC + trusted AERO
        self.assertEqual(p["stakersWeeklyUSD_human"], "3800.0000")
        self.assertAlmostEqual(p["apyPct"], 3_800 / (4_000_000 * 0.7) * 52 * 100, places=9)
        self.assertEqual(p["excludedTokens"], [
            {"address": THIN, "fundedUSD": 200.0, "poolDepthUsd": 30_000.0, "reason": "untrusted DEX price"},
            {"address": OLD_AERO, "fundedUSD": 800.0, "poolDepthUsd": 6_000_000.0, "reason": "untrusted DEX price"}])
        self.assertEqual([(x["address"], x["trusted"]) for x in p["dexPricedTokens"]],
                         [(AERO, True), (THIN, False), (OLD_AERO, False)])
        # a thinner pool than DEX_TRUSTED_DEPTH_USD, or no recorded depth (an older cache entry): AERO left out too
        with mock.patch.dict(os.environ, {"DEX_TRUSTED_DEPTH_USD": "10000000"}):
            self.assertEqual(compute_realized(EPOCH_15_OCT, funded, 1, 1, 0.7, 0.8)["fundedUSD_human"], "3000.0000")
        funded[1].pop("dexDepthUsd")
        self.assertEqual(compute_realized(EPOCH_15_OCT, funded, 1, 1, 0.7, 0.8)["fundedUSD_human"], "3000.0000")
        # the list comes from TRUSTED_DEX_TOKENS
        funded[1]["dexDepthUsd"] = 6_000_000.0
        with mock.patch.dict(os.environ, {"TRUSTED_DEX_TOKENS": f" 0x{OLD_AERO[2:].upper()} , {AERO},"}):
            self.assertEqual(trusted_dex_tokens(), {OLD_AERO, AERO})
            self.assertEqual(compute_realized(EPOCH_15_OCT, funded, 1, 1, 0.7, 0.8)["fundedUSD_human"], "4600.0000")
        with mock.patch.dict(os.environ, {"TRUSTED_DEX_TOKENS": ""}):
            self.assertEqual(trusted_dex_tokens(), {AERO})
        self.assertNotIn("staleReason", p)
        stale = compute_realized(EPOCH_15_OCT, funded, 4_000_000 * E18, 4_000_000 * E18, 0.7, 0.8, stale=True)
        self.assertIn(str(EPOCH_15_OCT), stale["staleReason"])

    def test_a_shorter_window_is_scaled_to_a_week(self):
        funded = [{"address": USDC, "amount": 2_000 * 10**6, "decimals": 6, "priceUsd": 1.0}]
        p = compute_realized(EPOCH_15_OCT, funded, 4_000_000 * E18, 4_000_000 * E18, 0.7, 0.8, span_days=2.0)
        self.assertEqual((p["fundedUSD_human"], p["stakersWeeklyUSD_human"]), ("2000.0000", "7000.0000"))
        self.assertEqual(p["estimatedWeeklyUSD_1e18"], str(8_750 * E18))
        self.assertAlmostEqual(p["apyPct"], 7_000 / (4_000_000 * 0.7) * 52 * 100, places=9)

    def test_no_stake_gives_zero_apy(self):
        funded = [{"address": USDC, "amount": 10**6, "decimals": 6, "priceUsd": 1.0}]
        self.assertEqual(compute_realized(EPOCH_15_OCT, funded, 0, 0, 0.7, 0.8)["apyPct"], 0.0)


class FakeDistributorWeb3:
    """Answers the EpochStakingDistributor views used by build_estimated_rewards."""

    def __init__(self, rewards, snapshot, supply_at_start, total_staked, iaero=IAERO):
        self.rewards, self.snapshot, self.supply = rewards, snapshot, supply_at_start
        self.total_staked, self.iaero = total_staked, iaero
        self.calls = []
        self.eth = mock.Mock(contract=self._contract)

    to_checksum_address = staticmethod(Web3.to_checksum_address)

    def _contract(self, address, abi=None):
        names = {e["name"] for e in abi}
        w3 = self

        class _Functions:
            def __getattr__(self, name):
                assert name in names, name

                def fn(*args):
                    w3.calls.append((name, args))
                    if name == "rewardsForEpoch":
                        val = w3.rewards.get((args[0].lower(), args[1]), 0)
                    elif name == "supplySnapshotAtEpochStart":
                        val = w3.snapshot.get(args[0], 0)
                    elif name == "totalSupplyAtEpochStart":
                        val = w3.supply.get(args[0], 0)
                    elif name == "totalStaked":
                        val = w3.total_staked
                    else:
                        val = Web3.to_checksum_address(w3.iaero)
                    return mock.Mock(call=lambda: val)
                return fn

        return mock.Mock(functions=_Functions())


class FakePriceFetcher:
    def __init__(self, prices):
        self.prices, self.asked = prices, []

    def fetch_batch(self, addrs):
        self.asked = list(addrs)
        return {a: {"priceUsd": self.prices.get(a, 0.0), "source": "test"} for a in addrs}


class BuildEstimatedRewardsTest(unittest.TestCase):
    def setUp(self):
        self.epochs_doc = {"epochs": {
            str(EPOCH_15_OCT): {"tokens": [USDC, OLD_AERO, ZERO_ADDRESS]},
            str(EPOCH_22_OCT): {"tokens": [USDC]},
        }}
        self.w3 = FakeDistributorWeb3(
            rewards={(USDC, EPOCH_15_OCT): 3_000 * 10**6, (OLD_AERO, EPOCH_15_OCT): 1_000 * E18,
                     (ZERO_ADDRESS, EPOCH_15_OCT): 1 * E18, (USDC, EPOCH_22_OCT): 99_999 * 10**6},
            snapshot={EPOCH_15_OCT: 4_000_000 * E18},
            supply_at_start={EPOCH_15_OCT: 1, EPOCH_22_OCT: 1},
            total_staked=4_200_000 * E18,
        )
        self.pf = FakePriceFetcher({USDC: 1.0, OLD_AERO: 0.8, WETH_ADDRESS: 4_000.0, AERO: 0.81, IAERO: 0.66})
        self.decimals = lambda toks: {USDC: 6, OLD_AERO: 18}

    def build(self, now_ts, **kw):
        return build_estimated_rewards(self.w3, DIST, self.epochs_doc, self.pf, self.decimals, now_ts=now_ts, **kw)

    def test_default_is_latest_funded_epoch(self):
        # daily run Thu 22 Oct 02:31: the 22 Oct funding (00:01) is the latest funded epoch
        p = self.build(EPOCH_22_OCT + 9060)
        self.assertEqual((p["epoch"], p["epochEnd"]), (EPOCH_22_OCT, EPOCH_22_OCT + WEEK))
        self.assertEqual((p["epochSelection"], p["stale"]), ("latest_funded", False))
        self.assertEqual(p["fundedUSD_human"], "99999.0000")
        # no cached snapshot -> falls back to totalSupplyAtEpochStart
        self.assertEqual(p["stakedAtEpochStart_1e18"], "1")

    def test_price_source_reaches_the_dex_fields(self):
        self.pf.fetch_batch = lambda addrs: {a: {"priceUsd": {USDC: 1.0, AERO: 0.81, IAERO: 0.66}.get(a, 0.0),
                                                 "source": "dex" if a == USDC else "llama", "dexDepthUsd": 40_000.0}
                                             for a in addrs}
        p = self.build(EPOCH_22_OCT + 9060)
        self.assertEqual(p["excludedTokens"], [{"address": USDC, "fundedUSD": 99_999.0, "poolDepthUsd": 40_000.0,
                                                "reason": "untrusted DEX price"}])
        self.assertEqual(p["fundedUSD_human"], "0.0000")

    def test_last_completed_mode_and_snapshot_denominator(self):
        p = self.build(EPOCH_22_OCT + 9060, epoch_mode="last_completed")
        self.assertEqual((p["epoch"], p["epochSelection"]), (EPOCH_15_OCT, "last_completed"))
        # $3000 USDC + 1000 x $0.8 + 1 ETH x $4000 (native ETH priced as WETH)
        self.assertEqual(p["fundedUSD_human"], "7800.0000")
        self.assertEqual(p["stakedAtEpochStart_1e18"], str(4_000_000 * E18))  # snapshot, not supply()=1
        self.assertAlmostEqual(p["apyPct"], 7_800 / (4_000_000 * 0.66) * 52 * 100, places=9)
        self.assertEqual(p["tvlUSD_1e18"], str(2_772_000 * E18))
        self.assertIn(WETH_ADDRESS, self.pf.asked)
        self.assertNotIn(ZERO_ADDRESS, self.pf.asked)
        self.assertNotIn(("rewardsForEpoch", (Web3.to_checksum_address(USDC), EPOCH_22_OCT)), self.w3.calls)

    def test_unknown_mode_falls_back_to_latest_funded(self):
        self.assertEqual(self.build(EPOCH_22_OCT + 9060, epoch_mode="bogus")["epochSelection"], "latest_funded")

    def test_previous_week_used_until_new_funding_lands(self):
        del self.epochs_doc["epochs"][str(EPOCH_22_OCT)]
        p = self.build(EPOCH_22_OCT + 30)
        self.assertEqual(p["epoch"], EPOCH_15_OCT)
        self.assertEqual(p["fundedUSD_human"], "7800.0000")

    def test_stale_latest_funded_epoch_reports_zero_with_that_epoch(self):
        # no funding for 29 Oct or 5 Nov: on 5 Nov 02:31 the latest funded epoch (22 Oct) is > 2 weeks old
        p = self.build(EPOCH_22_OCT + 2 * WEEK + 9060)
        self.assertEqual((p["epoch"], p["stale"]), (EPOCH_22_OCT, True))
        self.assertEqual((p["apyPct"], p["weeklyYieldPct"], p["fundedTokenCount"]), (0.0, 0.0, 0))
        self.assertNotIn("rewardsForEpoch", [c[0] for c in self.w3.calls])

    def test_unfunded_last_completed_epoch_reports_zero_with_epoch(self):
        p = self.build(EPOCH_22_OCT + 2 * WEEK + 60, epoch_mode="last_completed")
        self.assertEqual(p["epoch"], EPOCH_22_OCT + WEEK)
        self.assertEqual(p["apyPct"], 0.0)
        self.assertEqual(p["fundedTokenCount"], 0)


def _keeper_history():
    """Shape and formatting of the live file written by the rewards keeper (ultimate-keeper.mjs)."""
    return {
        "updatedAt": "2026-10-22T00:01:48.938Z",
        "latest": {"epoch": EPOCH_22_OCT, "apyPct": 12.589882348027016,
                   "tvlUSD_1e18": "3826910581165999363239397", "stakersWeeklyUSD_1e18": "9265452687173005722519"},
        "series": [
            {"epoch": EPOCH_15_OCT, "timestamp": 1792022518, "apyPct": 10.301653994505198,
             "tvlUSD_1e18": "4278836860930409070696684", "stakersWeeklyUSD_1e18": "8476749392353813493097"},
            {"epoch": EPOCH_22_OCT, "timestamp": 1792627308, "apyPct": 12.589882348027016,
             "tvlUSD_1e18": "3826910581165999363239397", "stakersWeeklyUSD_1e18": "9265452687173005722519"},
        ],
    }


def _payload(epoch, apy=13.8, funded=8_336 * E18, staked=3_135_570 * E18, tokens=36, stale=False):
    return {"epoch": epoch, "apyPct": apy, "fundedUSD_1e18": str(funded), "stakedUSD_1e18": str(staked),
            "fundedTokenCount": tokens, "stale": stale}


class YieldHistoryTest(unittest.TestCase):
    EPOCH_29_OCT = EPOCH_22_OCT + WEEK

    def test_never_rewrites_keeper_entry(self):
        doc, reason = merge_yield_history(_keeper_history(), _payload(EPOCH_22_OCT), EPOCH_22_OCT + 9060)
        self.assertIsNone(doc)
        self.assertIn("rewards keeper", reason)

    def test_appends_new_epoch_without_touching_history(self):
        cur = _keeper_history()
        before = copy.deepcopy(cur["series"])
        now = self.EPOCH_29_OCT + 9060
        doc, reason = merge_yield_history(cur, _payload(self.EPOCH_29_OCT), now)
        self.assertIn("appended", reason)
        self.assertEqual(doc["series"][:-1], before)                         # history byte-for-byte the same
        self.assertEqual(cur["series"], before)                              # input not mutated
        self.assertEqual(doc["series"][-1], {
            "epoch": self.EPOCH_29_OCT, "timestamp": now, "apyPct": 13.8,
            "tvlUSD_1e18": str(3_135_570 * E18), "stakersWeeklyUSD_1e18": str(8_336 * E18), "method": "realized"})
        self.assertEqual(doc["latest"]["epoch"], self.EPOCH_29_OCT)
        self.assertEqual(list(doc.keys()), ["updatedAt", "latest", "series"])  # keeper's key order
        self.assertEqual(doc["updatedAt"], "2026-10-29T02:31:00.000Z")

    def test_updates_only_its_own_latest_entry(self):
        doc, _ = merge_yield_history(_keeper_history(), _payload(self.EPOCH_29_OCT), self.EPOCH_29_OCT + 9060)
        before = copy.deepcopy(doc["series"][:-1])
        doc2, reason = merge_yield_history(doc, _payload(self.EPOCH_29_OCT, apy=14.1), self.EPOCH_29_OCT + 86400)
        self.assertIn("updated", reason)
        self.assertEqual(len(doc2["series"]), len(doc["series"]))
        self.assertEqual(doc2["series"][:-1], before)
        self.assertEqual(doc2["series"][-1]["apyPct"], 14.1)
        # identical numbers -> no write
        self.assertIsNone(merge_yield_history(doc2, _payload(self.EPOCH_29_OCT, apy=14.1), self.EPOCH_29_OCT + 2 * 86400)[0])

    def test_skips_stale_unfunded_or_older_epochs_and_unreadable_file(self):
        h = _keeper_history()
        self.assertIsNone(merge_yield_history(h, _payload(self.EPOCH_29_OCT, stale=True), 0)[0])
        self.assertIsNone(merge_yield_history(h, _payload(self.EPOCH_29_OCT, tokens=0), 0)[0])
        self.assertIsNone(merge_yield_history(h, _payload(EPOCH_15_OCT - WEEK), 0)[0])  # never back-fill history
        self.assertIsNone(merge_yield_history({}, _payload(self.EPOCH_29_OCT), 0)[0])   # API failure -> {} -> no wipe

    def test_serialisation_matches_keeper_format(self):
        # the keeper writes JSON.stringify(payload, null, 2); json.dumps(indent=2) reproduces it byte-for-byte
        raw = ('{\n  "updatedAt": "x",\n  "latest": {\n    "epoch": 1,\n    "apyPct": 12.589882348027016\n  },\n'
               '  "series": [\n    {\n      "epoch": 1,\n      "timestamp": 2,\n      "apyPct": 12.589882348027016,\n'
               '      "tvlUSD_1e18": "3826910581165999363239397"\n    }\n  ]\n}')
        self.assertEqual(dump_yield_history(json.loads(raw)), raw)


# main._update_realized_yield (the measured headline) is tested end to end in test_measured_headline.py.


if __name__ == "__main__":
    unittest.main()
