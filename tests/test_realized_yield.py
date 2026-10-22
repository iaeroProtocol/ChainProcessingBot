# test_realized_yield.py
# Unit tests for the realized-APY feed (data/estimated_rewards_usd.json + data/yield_history.json). No network.
# Run: python -m unittest discover -s tests
import base64
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
    build_window_rewards,
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

    def test_window_counts_funding_by_block_time(self):
        # RewardFunded events, whatever epoch they were booked to: the late 15 Oct booking at 22 Oct 05:00 counts
        events = [{"token": USDC, "epoch": EPOCH_15_OCT, "amount": 500 * 10**6, "timestamp": EPOCH_22_OCT - 60},
                  {"token": USDC.upper().replace("0X", "0x"), "epoch": EPOCH_15_OCT, "amount": 1_000 * 10**6,
                   "timestamp": EPOCH_22_OCT + 5 * 3600},
                  {"token": ZERO_ADDRESS, "epoch": EPOCH_22_OCT, "amount": E18 // 4, "timestamp": EPOCH_22_OCT + DAY},
                  {"token": USDC, "epoch": EPOCH_22_OCT, "amount": 2_000 * 10**6, "timestamp": EPOCH_22_OCT + 2 * DAY}]
        p = build_window_rewards(self.w3, DIST, events, EPOCH_22_OCT, EPOCH_22_OCT + 2 * DAY, self.pf, self.decimals,
                                 stake_epoch=EPOCH_15_OCT, now_ts=EPOCH_22_OCT + 2 * DAY)
        # $1,000 + 0.25 ETH ($1,000) in 2 days -> $7,000 a week; the event AT window_to is the next window's
        self.assertEqual((p["fundedUSD_human"], p["stakersWeeklyUSD_human"]), ("2000.0000", "7000.0000"))
        self.assertEqual(p["apyWindow"], {"from": EPOCH_22_OCT, "to": EPOCH_22_OCT + 2 * DAY, "spanDays": 2.0})
        self.assertEqual((p["epoch"], p["epochSelection"], p["stale"]), (EPOCH_15_OCT, "rolling_7d", False))
        self.assertEqual(p["stakedAtEpochStart_1e18"], str(4_000_000 * E18))   # stake at stake_epoch's start
        self.assertAlmostEqual(p["apyPct"], 7_000 / (4_000_000 * 0.66) * 52 * 100, places=9)

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


def _mock_repo(epochs_doc, history=None, estimated=None):
    repo = mock.Mock()

    def get_contents(path, ref=None):
        if path == "data/epochs.json" and epochs_doc is not None:
            return mock.Mock(content=base64.b64encode(json.dumps(epochs_doc).encode()).decode())
        if path == "data/yield_history.json" and history is not None:
            return mock.Mock(content=base64.b64encode(dump_yield_history(history).encode()).decode())
        if path == "data/estimated_rewards_usd.json" and estimated is not None:
            if isinstance(estimated, Exception):
                raise estimated
            return mock.Mock(content=base64.b64encode(json.dumps(estimated).encode()).decode())
        raise FileNotFoundError(path)
    repo.get_contents.side_effect = get_contents
    return repo


class MainHookTest(unittest.TestCase):
    """main._update_realized_yield: publishes via the updater; never publishes 0% on a bad epochs.json or a spike."""

    @classmethod
    def setUpClass(cls):
        import main  # noqa: F401  (imports github/dotenv; no network at import)
        cls.main = main

    def _repo(self, epochs_doc, history=None, estimated=None):
        return _mock_repo(epochs_doc, history, estimated)

    def _run(self, payload, env=None, epochs_doc=None, history=None, estimated=None, now=None, hist_payload=None):
        """now defaults to a week after payload's epoch, so payload's epoch is the last completed one; build() with an
        explicit epoch (the completed epoch for yield_history) returns hist_payload."""
        updater = mock.Mock(branch="main")
        envs = {"EPOCH_STAKING_DISTRIBUTOR": DIST, "LIVE_YIELD_ENABLED": "false"}
        envs.update(env or {})
        now = now if now is not None else int(payload["epoch"]) + WEEK + 9060
        with mock.patch.dict(os.environ, envs), mock.patch("time.time", return_value=now), \
             mock.patch.object(realized_yield, "build_estimated_rewards",
                               side_effect=lambda **kw: hist_payload if kw.get("epoch") is not None else payload) as b:
            changed = self.main._update_realized_yield(
                self._repo(epochs_doc if epochs_doc is not None else {"epochs": {"1": {"tokens": [USDC]}}}, history,
                           estimated),
                updater, mock.Mock(), mock.Mock())
        return changed, updater, b

    def test_writes_estimated_rewards_and_appends_yield_history(self):
        payload = dict(_payload(EPOCH_22_OCT + WEEK), tvlUSD_1e18="1")
        changed, updater, b = self._run(payload, history=_keeper_history())
        self.assertTrue(changed)
        self.assertEqual(b.call_args.kwargs["epoch_mode"], "latest_funded")
        updater.update_json.assert_called_once_with("data/estimated_rewards_usd.json", payload)
        path, content = updater.update_file.call_args.args
        self.assertEqual(path, "data/yield_history.json")
        self.assertEqual(updater.update_file.call_args.kwargs["commit_message"], f"Yield snapshot {EPOCH_22_OCT + WEEK}")
        written = json.loads(content)
        self.assertEqual(written["series"][:2], _keeper_history()["series"])
        self.assertEqual(written["series"][-1]["epoch"], EPOCH_22_OCT + WEEK)

    def test_epoch_mode_env_is_passed_through(self):
        _, _, b = self._run(_payload(EPOCH_15_OCT), env={"ESTIMATED_REWARDS_EPOCH": "last_completed",
                                                          "YIELD_HISTORY_ENABLED": "false"})
        self.assertEqual(b.call_args.kwargs["epoch_mode"], "last_completed")

    def test_keeper_entry_for_same_epoch_is_left_alone(self):
        changed, updater, _ = self._run(_payload(EPOCH_22_OCT), history=_keeper_history())
        self.assertTrue(changed)                          # estimated_rewards_usd.json still written
        updater.update_file.assert_not_called()           # yield_history.json untouched

    def test_apy_spike_is_not_published(self):
        changed, updater, _ = self._run(_payload(EPOCH_22_OCT + WEEK, apy=812.0), history=_keeper_history())
        self.assertFalse(changed)
        updater.update_json.assert_not_called()
        updater.update_file.assert_not_called()

    def test_unpriced_core_tokens_are_not_published(self):
        payload = dict(_payload(EPOCH_22_OCT + WEEK, apy=0.0), aeroPrice_1e18="0", iaeroPrice_1e18="0",
                       stakedAtEpochStart_1e18=str(4 * 10**24), stakedUSD_1e18="0")
        changed, updater, _ = self._run(payload, history=_keeper_history())
        self.assertFalse(changed)
        updater.update_json.assert_not_called()
        updater.update_file.assert_not_called()

    def test_in_progress_epoch_is_never_written_to_yield_history(self):
        cur = EPOCH_22_OCT + 2 * WEEK                                  # 5 Nov, funding partial so far
        done = dict(_payload(EPOCH_22_OCT + WEEK, apy=14.2), method="realized")
        epochs = {"epochs": {str(EPOCH_22_OCT + WEEK): {"tokens": [USDC]}, str(cur): {"tokens": [USDC]}}}
        changed, updater, b = self._run(_payload(cur, apy=3.0), now=cur + 9060, epochs_doc=epochs,
                                        history=_keeper_history(), hist_payload=done)
        self.assertEqual({k: b.call_args_list[-1].kwargs[k] for k in ("epoch", "epoch_mode")},
                         {"epoch": EPOCH_22_OCT + WEEK, "epoch_mode": "last_completed"})   # completed epoch read again
        updater.update_json.assert_called_once()                       # 3% published as today's figure
        series = json.loads(updater.update_file.call_args.args[1])["series"]
        self.assertEqual([(x["epoch"], x["apyPct"]) for x in series[-2:]], [(EPOCH_22_OCT, 12.589882348027016),
                                                                            (EPOCH_22_OCT + WEEK, 14.2)])
        # the completed epoch has no funding in epochs.json -> no extra read, no entry
        changed, updater, b = self._run(_payload(cur, apy=3.0), now=cur + 9060, history=_keeper_history(),
                                        epochs_doc={"epochs": {str(cur): {"tokens": [USDC]}}})
        self.assertEqual(b.call_count, 1)
        updater.update_file.assert_not_called()
        # a completed-epoch figure failing the sanity guard is not written
        changed, updater, _ = self._run(_payload(cur, apy=3.0), now=cur + 9060, epochs_doc=epochs,
                                        history=_keeper_history(), hist_payload=_payload(EPOCH_22_OCT + WEEK, apy=812.0))
        updater.update_file.assert_not_called()
        updater.update_json.assert_called_once()

    def test_unreadable_previous_file_is_not_overwritten(self):
        err = Exception('503 {"message": "Service Unavailable"}')
        with mock.patch.object(self.main, "_build_live_block") as bl:
            changed, updater, _ = self._run(_payload(EPOCH_22_OCT + WEEK), env={"LIVE_YIELD_ENABLED": "true"},
                                            history=_keeper_history(), estimated=err)
        self.assertFalse(changed)
        bl.assert_not_called()
        updater.update_json.assert_not_called()
        updater.update_file.assert_not_called()

    def test_live_failure_keeps_previous_block_flagged_stale(self):
        prev_live = {"method": "live_position", "stale": False, "stakeId": 1584, "history": [{"asOf": 1}],
                     "gauges": [{"chainId": 8453, "gauge": "0x" + "a3" * 20}]}
        with mock.patch.object(self.main, "_build_live_block", side_effect=RuntimeError("429 Too Many Requests")) as bl:
            changed, updater, _ = self._run(_payload(EPOCH_22_OCT + WEEK), env={"LIVE_YIELD_ENABLED": "true"},
                                            history=_keeper_history(), estimated={"apyPct": 13.0, "live": prev_live})
        self.assertTrue(changed)
        self.assertEqual(bl.call_args.args[3], prev_live)
        self.assertEqual(updater.update_json.call_args.args[1]["live"], dict(prev_live, stale=True))

    def test_skips_when_epochs_json_unavailable(self):
        updater = mock.Mock(branch="main")
        with mock.patch.dict(os.environ, {"EPOCH_STAKING_DISTRIBUTOR": DIST}), \
             mock.patch.object(realized_yield, "build_estimated_rewards") as b:
            changed = self.main._update_realized_yield(self._repo(None), updater, mock.Mock(), mock.Mock())
        self.assertFalse(changed)
        b.assert_not_called()
        updater.update_json.assert_not_called()

    def test_each_file_can_be_disabled(self):
        _, updater, _ = self._run(_payload(EPOCH_22_OCT + WEEK), env={"ESTIMATED_REWARDS_ENABLED": "false"},
                                  history=_keeper_history())
        updater.update_json.assert_not_called()
        updater.update_file.assert_called_once()
        _, updater, _ = self._run(_payload(EPOCH_22_OCT + WEEK), env={"YIELD_HISTORY_ENABLED": "false"},
                                  history=_keeper_history())
        updater.update_json.assert_called_once()
        updater.update_file.assert_not_called()
        changed, _, b = self._run(_payload(EPOCH_22_OCT + WEEK), env={"ESTIMATED_REWARDS_ENABLED": "false",
                                                                       "YIELD_HISTORY_ENABLED": "false"})
        self.assertFalse(changed)
        b.assert_not_called()

    def test_live_block_is_added_without_touching_apy_or_history(self):
        payload = dict(_payload(EPOCH_22_OCT + WEEK), aeroPrice_1e18=str(8 * 10**17), stakedUSD_1e18=str(3 * 10**24))
        live = {"method": "live_position", "positionAprPct": 30.0}
        with mock.patch.object(self.main, "_build_live_block", return_value=live) as bl:
            changed, updater, _ = self._run(payload, env={"LIVE_YIELD_ENABLED": "true"}, history=_keeper_history())
        self.assertTrue(changed)
        bl.assert_called_once()
        written = updater.update_json.call_args.args[1]
        self.assertEqual(written["live"], live)
        self.assertEqual({k: v for k, v in written.items() if k != "live"}, payload)   # apyPct etc. unchanged
        self.assertNotIn("live", json.loads(updater.update_file.call_args.args[1])["series"][-1])

    def test_live_failure_still_publishes_realized_file(self):
        payload = _payload(EPOCH_22_OCT + WEEK)
        with mock.patch.object(self.main, "_build_live_block", side_effect=RuntimeError("rpc down")):
            changed, updater, _ = self._run(payload, env={"LIVE_YIELD_ENABLED": "true", "YIELD_HISTORY_ENABLED": "false"})
        self.assertTrue(changed)
        updater.update_json.assert_called_once_with("data/estimated_rewards_usd.json", payload)

    def test_live_can_be_disabled(self):
        with mock.patch.object(self.main, "_build_live_block") as bl:
            self._run(_payload(EPOCH_22_OCT + WEEK), env={"LIVE_YIELD_ENABLED": "false", "YIELD_HISTORY_ENABLED": "false"})
        bl.assert_not_called()



class RollingModeTest(unittest.TestCase):
    """ROLLING_SINCE_TS: the headline is the RewardFunded events of the last 7 days (block time) annualised over the
    window, never counting a catch-up funding (the first after ROLLING_SINCE_TS or after 7 days without funding);
    yield_history gets each completed epoch the same way. The daily harvester funds $1,000 of USDC at 06:00 UTC into
    the running epoch; 4M iAERO staked at $0.66 -> 13.79%. The 15 Oct epoch holds a $7,000 Aerodrome-era week."""
    SINCE = EPOCH_22_OCT + 6 * 3600                       # first daily harvest, Thu 22 Oct 06:00
    STAKED = 4_000_000 * E18
    APY = 7_000 / (4_000_000 * 0.66) * 52 * 100
    LEGACY = {(USDC, EPOCH_15_OCT): 7_000 * 10**6}       # rewardsForEpoch only (before the cutoff, never an event)

    @classmethod
    def setUpClass(cls):
        import main  # noqa: F401
        cls.main = main

    def _daily(self, start, until, amount=1_000 * 10**6):
        out, ts = [], start
        while ts < until:
            out.append({"token": USDC, "epoch": epoch_start(ts), "amount": amount, "timestamp": ts, "blockNumber": ts // 2})
            ts += DAY
        return out

    def _run(self, now, since=SINCE, events=None, legacy=LEGACY, history=None, scan_error=None, env=None):
        events = self._daily(self.SINCE, now) if events is None else [e for e in events if e["timestamp"] < now]
        rewards = dict(legacy or {})
        for e in events:
            rewards[(USDC, e["epoch"])] = rewards.get((USDC, e["epoch"]), 0) + e["amount"]
        w3 = FakeDistributorWeb3(rewards=rewards, snapshot={EPOCH_22_OCT + k * WEEK: self.STAKED for k in range(-2, 5)},
                                 supply_at_start={}, total_staked=self.STAKED)
        scanner = mock.Mock(w3=w3)
        scanner.decimals_map.side_effect = lambda toks, **k: {USDC: 6}
        scanner.reward_funded_events.side_effect = scan_error or (
            lambda dist, frm, to: [e for e in events if frm <= e["timestamp"] <= to])
        repo = _mock_repo({"epochs": {str(ep): {"tokens": [USDC]} for (_, ep) in rewards}},
                          history if history is not None else _keeper_history())
        updater = mock.Mock(branch="main")
        envs = {"EPOCH_STAKING_DISTRIBUTOR": DIST, "LIVE_YIELD_ENABLED": "false",
                "ROLLING_SINCE_TS": "" if since is None else str(since)}
        envs.update(env or {})
        with mock.patch.dict(os.environ, envs), mock.patch("time.time", return_value=now):
            self.main._update_realized_yield(repo, updater, scanner,
                                             FakePriceFetcher({USDC: 1.0, AERO: 0.81, IAERO: 0.66}))
        written = updater.update_json.call_args.args[1] if updater.update_json.called else None
        hist = json.loads(updater.update_file.call_args.args[1]) if updater.update_file.called else None
        return written, hist, scanner

    def test_headline_is_the_last_7_days(self):
        now = EPOCH_22_OCT + WEEK + 3 * DAY + 9060          # Sun 1 Nov 02:31: 3 harvests so far in the 29 Oct epoch
        p, _, scanner = self._run(now)
        self.assertAlmostEqual(p["apyPct"], self.APY, places=6)
        self.assertEqual(p["stakersWeeklyUSD_human"], "7000.0000")
        self.assertEqual(p["apyWindow"], {"from": now - WEEK, "to": now, "spanDays": 7.0, "afterCatchUp": None})
        self.assertEqual((p["epochSelection"], p["epoch"]), ("rolling_7d", EPOCH_22_OCT + WEEK))
        self.assertEqual(scanner.reward_funded_events.call_args.args, (DIST, self.SINCE, now))
        # the per-epoch mode shows the partial week
        p, _, scanner = self._run(now, since=None)
        self.assertAlmostEqual(p["apyPct"], self.APY * 3 / 7, places=6)
        scanner.reward_funded_events.assert_not_called()
        self.assertNotIn("apyWindow", p)

    def test_catch_up_funding_is_never_counted(self):
        # the first run claims 3 days of accrual ($3,000); the daily ones after it pay for one day each
        events = [dict(e, amount=3_000 * 10**6) if e["timestamp"] == self.SINCE else e
                  for e in self._daily(self.SINCE, self.SINCE + 7 * DAY)]
        now = self.SINCE + 2 * DAY + 12 * 3600
        p, _, _ = self._run(now, events=events)
        self.assertEqual(p["apyWindow"], {"from": self.SINCE + 1, "to": self.SINCE + 2 * DAY + 1, "spanDays": 2.0,
                                          "afterCatchUp": self.SINCE})
        self.assertAlmostEqual(p["apyPct"], self.APY, places=6)
        # once the catch-up is over 7 days old, the plain window (it is outside)
        p, _, _ = self._run(self.SINCE + 7 * DAY + 3600, events=events + self._daily(self.SINCE + 7 * DAY, self.SINCE + 8 * DAY))
        self.assertEqual(p["apyWindow"]["afterCatchUp"], None)
        self.assertAlmostEqual(p["apyPct"], self.APY, places=6)

    def test_until_a_day_after_the_catch_up_the_last_completed_week(self):
        for now in (self.SINCE - 3600, self.SINCE + 12 * 3600):      # before the first funding, and just after it
            p, _, _ = self._run(now)
            self.assertNotIn("apyWindow", p)
            self.assertEqual((p["epoch"], p["epochSelection"]), (EPOCH_15_OCT, "last_completed"))
            self.assertAlmostEqual(p["apyPct"], self.APY, places=6)       # the 15 Oct week, $7,000
            self.assertIn("rollingFallback", p)
        # no completed week to fall back on either: the previous headline is kept (nothing written), never a 0
        p, _, _ = self._run(self.SINCE + 12 * 3600, legacy={})
        self.assertIsNone(p)

    def test_catch_up_booked_to_the_completed_epoch_is_left_out_of_the_fallback(self):
        # launched Wed 28 Oct 06:00 with a 6-day catch-up booked to the 22 Oct epoch, which also holds an Aerodrome week
        launch = EPOCH_22_OCT + 6 * DAY + 6 * 3600
        events = [{"token": USDC, "epoch": EPOCH_22_OCT, "amount": 6_000 * 10**6, "timestamp": launch, "blockNumber": 1}]
        legacy = {(USDC, EPOCH_22_OCT): 7_000 * 10**6}
        p, _, _ = self._run(EPOCH_22_OCT + WEEK + 9060, since=launch, events=events, legacy=legacy)   # Thu 29 Oct 02:31
        self.assertEqual((p["epoch"], p["fundedUSD_human"]), (EPOCH_22_OCT, "7000.0000"))

    def test_a_week_without_funding_falls_back_and_the_next_funding_is_a_catch_up(self):
        events = self._daily(self.SINCE, self.SINCE + 3 * DAY)              # 22..24 Oct, then an outage
        resume = self.SINCE + 12 * DAY                                      # Tue 3 Nov: claims 9 days at once
        events += [{"token": USDC, "epoch": epoch_start(resume), "amount": 9_000 * 10**6, "timestamp": resume,
                    "blockNumber": 2}] + self._daily(resume + DAY, resume + 5 * DAY)
        p, _, _ = self._run(self.SINCE + 11 * DAY, events=events)           # Mon 2 Nov: nothing in 7 days
        self.assertEqual(p["epochSelection"], "last_completed")
        self.assertNotEqual(p["apyPct"], 0.0)
        p, _, _ = self._run(resume + 3 * DAY + 3600, events=events)         # Fri 6 Nov: the 9-day claim is left out
        self.assertEqual(p["apyWindow"]["afterCatchUp"], resume)
        self.assertAlmostEqual(p["apyPct"], self.APY, places=6)

    def test_rejected_rolling_since_keeps_the_per_epoch_mode(self):
        now = EPOCH_22_OCT + WEEK + 3 * DAY + 9060
        for bad in ("not-a-timestamp", "0", "1", "-5", str(EPOCH_22_OCT), str(1792627305),       # before the cutoff
                    str(self.SINCE * 1000)):                                                    # milliseconds
            with self.assertLogs("main", "ERROR") as logs:
                p, _, scanner = self._run(now, since=bad)
            self.assertNotIn("apyWindow", p, bad)
            self.assertEqual(p["epochSelection"], "latest_funded", bad)
            scanner.reward_funded_events.assert_not_called()
            self.assertTrue(any("ROLLING_SINCE_TS" in m and "rejected" in m for m in logs.output), logs.output)
        p, _, _ = self._run(now, since=str(1792627306))                     # the cutoff itself is accepted
        self.assertIn("apyWindow", p)
        p, _, _ = self._run(now, since=bad, env={"ROLLING_CUTOFF_TS": "1"})  # the cutoff is configurable
        self.assertNotIn("apyWindow", p)                                    # (ms is still rejected)

    def test_scan_failure_publishes_nothing(self):
        p, hist, _ = self._run(EPOCH_22_OCT + WEEK + 3 * DAY, scan_error=RuntimeError("eth_getLogs 429"))
        self.assertEqual((p, hist), (None, None))

    def test_yield_history_entry_per_completed_epoch(self):
        now = EPOCH_22_OCT + 2 * WEEK + 9060                   # Thu 5 Nov 02:31: the 29 Oct epoch is complete
        _, hist, _ = self._run(now)
        last = hist["series"][-1]
        self.assertEqual(last["epoch"], EPOCH_22_OCT + WEEK)
        self.assertAlmostEqual(last["apyPct"], self.APY, places=6)          # 7 harvests in 7 days
        self.assertEqual(last["stakersWeeklyUSD_1e18"], str(7_000 * E18))
        # harvester started Sun 1 Nov 06:00 (a 3-day catch-up): 2..4 Nov over the 3 days after it
        start = EPOCH_22_OCT + WEEK + 3 * DAY + 6 * 3600
        events = [dict(e, amount=3_000 * 10**6) if e["timestamp"] == start else e for e in self._daily(start, now)]
        _, hist, _ = self._run(now, since=start, events=events)
        self.assertAlmostEqual(hist["series"][-1]["apyPct"], self.APY, places=6)
        # started Wed 4 Nov 06:00: only the catch-up in the epoch -> no entry
        _, hist, _ = self._run(now, since=EPOCH_22_OCT + WEEK + 6 * DAY + 6 * 3600)
        self.assertIsNone(hist)

    def test_catch_up_stays_out_when_rolling_since_is_older_than_two_weeks(self):
        # ROLLING_SINCE_TS 22 Oct 06:00 but the first funding only Thu 29 Oct 06:00, claiming 7 days ($7,000) into the
        # 29 Oct epoch. On 6 Nov the 29 Oct entry is rewritten; a scan starting 2 weeks back (23 Oct 02:31) saw only
        # 6.1 quiet days before the catch-up and counted it
        launch = EPOCH_22_OCT + WEEK + 6 * 3600
        events = [{"token": USDC, "epoch": EPOCH_22_OCT + WEEK, "amount": 7_000 * 10**6, "timestamp": launch,
                   "blockNumber": 1}] + self._daily(launch + DAY, launch + 9 * DAY)
        for now in (EPOCH_22_OCT + 2 * WEEK + 9060, EPOCH_22_OCT + 2 * WEEK + DAY + 9060):
            _, hist, scanner = self._run(now, events=events)
            self.assertEqual(hist["series"][-1]["epoch"], EPOCH_22_OCT + WEEK)
            self.assertAlmostEqual(hist["series"][-1]["apyPct"], self.APY, places=6)
            self.assertEqual(scanner.reward_funded_events.call_args.args[1], self.SINCE)


class RollingHelpersTest(unittest.TestCase):
    def test_funding_anchors(self):
        from realized_yield import funding_anchors
        t = [100, 100, 200 + DAY, 300 + 2 * DAY, 300 + 10 * DAY, 300 + 11 * DAY]
        self.assertEqual(funding_anchors(t, since=50, scan_from=50), [100, 300 + 10 * DAY])
        self.assertEqual(funding_anchors(t, since=150, scan_from=150), [200 + DAY, 300 + 10 * DAY])
        # the scan began after since: its first funding is a catch-up only after 7 days with none
        self.assertEqual(funding_anchors(t, since=50, scan_from=90), [300 + 10 * DAY])
        self.assertEqual(funding_anchors([], since=50, scan_from=50), [])

    def test_rolling_bounds(self):
        from realized_yield import rolling_bounds
        t = [0, DAY, 2 * DAY, 3 * DAY]
        self.assertEqual(rolling_bounds(t, [0], 0, 7 * DAY), (1, 3 * DAY + 1))       # after the catch-up
        self.assertEqual(rolling_bounds(t[:1] + [DAY // 2], [0], 0, 7 * DAY), None)   # under a day after it
        self.assertEqual(rolling_bounds(t, [0], DAY, 8 * DAY), (DAY, 8 * DAY))        # catch-up before the window
        self.assertEqual(rolling_bounds(t, [], 10 * DAY, 17 * DAY), None)             # nothing in the window


if __name__ == "__main__":
    unittest.main()
