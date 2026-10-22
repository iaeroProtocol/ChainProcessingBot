# test_review_findings.py
# Independent review of PR #5: H-1 (F1), M-1 (F2), M-2 (F3), M-3 (F4). Each test asserts the SAFE behaviour and
# failed on a1503e9. The two F3 tests are adapted (see their comments), and F2's / F4's main tests run on the
# measured-headline harness; the review's Low-finding tests are not here.
# No network. Run: python -m pytest -p no:pytest_ethereum tests/test_review_findings.py -v
import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import position_earnings as pe  # noqa: E402
import price_fetcher  # noqa: E402
import realized_yield  # noqa: E402
from realized_yield import compute_realized, is_sane_apy  # noqa: E402
from test_price_fetcher import FakeChain, fake_web3_cls, USDC as USDC_CS, WETH as WETH_CS  # noqa: E402
from test_price_fetcher import AERO_VOLATILE_FACTORY  # noqa: E402
from test_position_earnings import (_chain, _g2, _live, T0, DAY, G_CL, USDC, META, PRICES)  # noqa: E402

E18 = 10 ** 18
CBBTC = "0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf"
LONGTAIL = "0x00000000000000000000000000000000000Bad01"
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
EPOCH_22_OCT = 1792627200


def _pf(chain, **kw):
    cache = os.path.join(tempfile.mkdtemp(), "price_cache.json")
    with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(chain)):
        pf = price_fetcher.PriceFetcher(cache_file=cache, rpc_url="http://fake", usdc=USDC_CS, weth=WETH_CS,
                                        aerodrome_factory=price_fetcher.AERODROME_FACTORY, **kw)
    pf._fetch_llama = lambda addrs: {}
    pf._fetch_coingecko = lambda addrs: {}
    return pf


class F1_DexPricing(unittest.TestCase):
    """F1: the DEX fallback quotes 1 whole token in the FIRST Aero pool it finds, however thin."""

    def test_cbbtc_priced_from_thin_aero_pool(self):
        # mainnet reserves read 2026-10-22 13:3x UTC (dry run):
        #   Aero volatile cbBTC/USDC 0x4AE90aFd...: 457.302567 USDC / 0.00558929 cbBTC
        #   Aerodrome volatile cbBTC/USDC 0x9c38b55f...: 128,827.784341 USDC / 1.57511593 cbBTC
        ch = FakeChain()
        ch.decimals[CBBTC] = 8
        ch.add_aero_pool(AERO_VOLATILE_FACTORY, CBBTC, 558_929, USDC_CS, 457_302_567)
        ch.add_aerodrome_pool(False, CBBTC, 157_511_593, USDC_CS, 128_827_784_341)
        px = _pf(ch).fetch_batch([CBBTC.lower()])[CBBTC.lower()]["priceUsd"]
        # DefiLlama (rejected by MAX_PRICE_USD=50000) says $81,756
        self.assertGreater(px, 40_000, f"cbBTC priced ${px:.2f} from a $900 Aero pool")

    def test_llama_btc_price_rejected_by_default_cap(self):
        pf = price_fetcher.PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"))  # main.py default cap 50000
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"coins": {f"base:{CBBTC.lower()}": {"price": 81756.5, "decimals": 8, "confidence": 0.99}}}
        with mock.patch.object(price_fetcher.requests, "get", return_value=resp):
            got = pf._fetch_llama([CBBTC.lower()])
        self.assertIn(CBBTC.lower(), got, "DefiLlama's cbBTC price is dropped by max_price_usd=50000")

    def test_skewed_attacker_pool_inflates_apy_but_passes_guard(self):
        # an attacker creates an Aero pool for a funded long-tail token with 0.01 token : 200 USDC
        ch = FakeChain()
        ch.decimals[LONGTAIL] = 18
        ch.add_aero_pool(AERO_VOLATILE_FACTORY, LONGTAIL, 10**16, USDC_CS, 200 * 10**6)
        px = _pf(ch).fetch_batch([LONGTAIL.lower()])[LONGTAIL.lower()]["priceUsd"]
        funded = [{"address": USDC.lower(), "amount": 8_300 * 10**6, "decimals": 6, "priceUsd": 1.0},
                  {"address": LONGTAIL.lower(), "amount": 1_000 * E18, "decimals": 18, "priceUsd": px}]
        p = compute_realized(EPOCH_22_OCT, funded, 4_710_927 * E18, 4_710_930 * E18, 0.6656, 0.802)
        honest = 8_300 / (4_710_927 * 0.6656) * 52 * 100
        self.assertLess(p["apyPct"], 2 * honest, f"apy {p['apyPct']:.1f}% (honest {honest:.1f}%), "
                                                 f"guard passes={is_sane_apy(p)}; token priced ${px:.2f}")


class F2_ZeroPrices(unittest.TestCase):
    """F2: zero prices give apyPct 0 and tvlUSD 0, which pass the guard and are published."""

    def test_zero_prices_are_not_sane(self):
        funded = [{"address": USDC.lower(), "amount": 8_300 * 10**6, "decimals": 6, "priceUsd": 0.0}]
        p = compute_realized(EPOCH_22_OCT, funded, 4_710_927 * E18, 4_710_930 * E18, iaero_price=0.0, aero_price=0.0)
        self.assertEqual((p["apyPct"], p["tvlUSD_1e18"]), (0.0, "0"))
        self.assertFalse(is_sane_apy(p), "apyPct 0 / tvlUSD_1e18 '0' from failed prices would be published")

    def test_main_publishes_zero_apy_and_tvl_when_prices_fail(self):
        # adapted (measured headline): main runs on test_measured_headline's simulated chains; every price fails
        from test_measured_headline import World, FakePF, RUN0, DAY as D, EST, previous_headline
        w = World(prev=False, base_pf=FakePF({}), chain_prices={1: FakePF({}), 4663: FakePF({})})
        for d in range(3):
            w.run(RUN0 + d * D)
        self.assertNotIn(EST, w.repo.files, "published apyPct / tvlUSD from failed prices")
        # with a previous headline: kept as it was, never replaced by 0
        w = World(base_pf=FakePF({}), chain_prices={1: FakePF({}), 4663: FakePF({})})
        for d in range(3):
            doc = w.run(RUN0 + d * D)
        prev = previous_headline()
        self.assertEqual((doc["apyPct"], doc["tvlUSD_1e18"], doc["apySource"]), (prev["apyPct"], prev["tvlUSD_1e18"], "kept"))

    def test_cached_zero_price_is_reused_without_retry(self):
        cache = os.path.join(tempfile.mkdtemp(), "price_cache.json")
        a = price_fetcher.PriceFetcher(cache_file=cache)
        a._fetch_llama = lambda addrs: {}          # llama outage during the rewards pass (02:31)
        a._fetch_coingecko = lambda addrs: {}
        a.fetch_batch([USDC.lower()])
        b = price_fetcher.PriceFetcher(cache_file=cache)   # er_pf, built ~4 min later from the same file
        b._fetch_llama = mock.Mock(side_effect=lambda addrs: {x: {"priceUsd": 1.0, "updatedAt": 0, "source": "llama"} for x in addrs})
        b._fetch_coingecko = lambda addrs: {}
        got = b.fetch_batch([USDC.lower()])[USDC.lower()]["priceUsd"]
        self.assertEqual(got, 1.0, "a cached 0.0 ('source': 'none') is served for ttl seconds; llama is not retried")


class F3_TrailingPoisoning(unittest.TestCase):
    """F3: a history point taken while claims were not scanned (or a gauge was missing) inflates the next window."""
    NOW = T0 + 10 * DAY

    def test_point_without_claims_inflates_next_24h(self):
        # day 8: 100 USDC claimed so far + 10 unclaimed, but eth_getLogs refused -> claimed = {} in the point.
        # Adapted: the review built day 8 through _live, whose chain always says claimsScanned=True; here the chain
        # says what read_chain_position returns when eth_getLogs is refused (claimsScanned=False).
        ch8 = _chain(8453, T0, self.NOW - 2 * DAY, 1, [_g2(G_CL, fees={USDC: 10 * 10**6})])
        ch8["claimsScanned"] = False
        d8 = pe.value_live([ch8], META, PRICES, 1584, 1_000_000 * E18, 0.8, 600_000.0, now_ts=self.NOW - 2 * DAY)
        # day 9: claims scanned again: 100 claimed + 20 unclaimed = 120 cumulative; true accrual over 24 h = 10 USDC
        d9 = _live([_g2(G_CL, fees={USDC: 20 * 10**6}, cfees={USDC: 100 * 10**6})], self.NOW - DAY, d8["history"])
        t24 = d9["trailing"]["24h"]
        self.assertTrue(t24 is None or t24["usdPerDay"] < 20.0,
                        f"trailing 24h = ${(t24 or {}).get('usdPerDay')}/day vs true $10/day "
                        f"(claimsComplete={(t24 or {}).get('claimsComplete')})")

    def test_gauge_missing_from_snapshot_counts_its_whole_cumulative(self):
        # yesterday's point lost gauge G_CL (e.g. its VRM read failed and the row was dropped); it has earned since T0
        snap = {"asOf": self.NOW - DAY, "chains": [8453], "accruedUSD": 0, "feesCumUSD": 0, "gauges": {},
                "complete": True}           # adapted (review 8 M-1): only complete points end a window
        live = _live([_g2(G_CL, fees={USDC: 1_000 * 10**6})], self.NOW, [snap])
        rate = live["trailing"]["24h"]["usdPerDay"]
        self.assertLess(rate, 500.0, f"10 days of earnings (${rate:.0f}) reported as one day's")
        # adapted: the review asserted partial=False (the unflagged state it demonstrated); the gauge left out flags it
        self.assertTrue(live["trailing"]["24h"]["partial"])


class F4_LiveHistoryLoss(unittest.TestCase):
    """F4: any live-block failure publishes the file WITHOUT `live`, wiping live.history and the re-vote gauge list."""

    def test_live_failure_keeps_previous_live_block(self):
        # adapted (measured headline): main runs on test_measured_headline's simulated chains
        from test_measured_headline import World, RUN0, DAY as D
        w = World()
        before = [w.run(RUN0 + d * D) for d in range(2)][-1]
        written = w.run(RUN0 + 2 * D, live_error=RuntimeError("token_meta: 429 Too Many Requests"))
        self.assertIn("live", written, "previous live.history and gauge list are dropped from the published file")
        self.assertEqual(written["live"]["history"], before["live"]["history"])
        self.assertTrue(written["live"]["stale"])


if __name__ == "__main__":
    unittest.main()
