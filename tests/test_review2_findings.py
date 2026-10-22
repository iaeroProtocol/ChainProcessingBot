# test_review2_findings.py
# Second independent review of PR #5 at 37ae513: M-A, the 3x guard locked onto the first low value and froze the feed.
# The review's RA_* tests, run end to end through main._update_realized_yield (in-memory repo, no network) so they
# don't depend on the guard's signature; each asserts the SAFE behaviour and failed on 37ae513. Adaptations are noted
# per test. The review's other tests (Lows) are not here. RD_* covers the follow-up: trusted (deep-pool) DEX prices
# (after round 3: an untrusted DEX price is left out of the figures, never a reason to keep them stale).
# Run: python -m pytest -p no:pytest_ethereum -q tests/test_review2_findings.py
import base64
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

import main  # noqa: E402
import price_fetcher  # noqa: E402
import realized_yield  # noqa: E402
from realized_yield import WEEK  # noqa: E402
from test_realized_yield import FakeDistributorWeb3, FakePriceFetcher, _keeper_history  # noqa: E402
from test_price_fetcher import FakeChain, fake_web3_cls, AERO_VOLATILE_FACTORY  # noqa: E402
from test_price_fetcher import USDC as USDC_CS, WETH as WETH_CS, AERO as AERO_CS  # noqa: E402

E18 = 10 ** 18
DAY = 86400
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
WETH = "0x4200000000000000000000000000000000000006"
IAERO = "0x81034fb34009115f215f5d5f564aac9ffa46a1dc"
E_22_OCT = 1792627200
E_29_OCT = E_22_OCT + WEEK
E_05_NOV = E_29_OCT + WEEK
STAKED_RAW = 4_710_927 * E18          # staked iAERO at epoch start (live value)
IAERO_PX = 0.6656
STAKED_USD = 4_710_927 * IAERO_PX


def usdc_for(apy: float) -> int:
    """Raw USDC funding that gives `apy` % on the staked iAERO."""
    return round(apy / 100 / 52 * STAKED_USD * 10 ** 6)


# in-memory GitHub repo/updater pair (same shape as the review's)
class _F:
    def __init__(self, text):
        self.content = base64.b64encode(text.encode()).decode()
        self.sha = "x"


class FakeRepo:
    def __init__(self, files):
        self.files = dict(files)

    def get_contents(self, path, ref=None):
        if path not in self.files:
            e = Exception("404 Not Found")
            e.status = 404
            raise e
        return _F(self.files[path])


class FakeUpdater:
    branch = "main"

    def __init__(self, repo):
        self.repo, self.writes = repo, []

    def update_file(self, path, content, commit_message=None):
        self.writes.append(path)
        self.repo.files[path] = content

    def update_json(self, path, data):
        self.update_file(path, json.dumps(dict(data, lastUpdated="X", updateTimestamp=0), indent=2, sort_keys=True))


def _run_bot(repo, updater, funded_prices, rewards, now, env=None, pf=None):
    """One daily run of _update_realized_yield (adapted: the stake snapshot exists for every epoch used; pf replaces
    the fixed-price fetcher)."""
    w3 = FakeDistributorWeb3(rewards=rewards, snapshot={e: STAKED_RAW for e in (E_22_OCT, E_29_OCT, E_05_NOV)},
                             supply_at_start={}, total_staked=STAKED_RAW)
    scanner = mock.Mock(w3=w3)
    scanner.decimals_map.side_effect = lambda toks, **k: {USDC: 6, WETH: 18}
    prices = dict(funded_prices or {}, **{realized_yield.AERO_ADDRESS.lower(): 0.81, IAERO: IAERO_PX})
    e = {"EPOCH_STAKING_DISTRIBUTOR": DIST, "LIVE_YIELD_ENABLED": "false", "YIELD_HISTORY_ENABLED": "true"}
    e.update(env or {})
    with mock.patch.dict(os.environ, e), mock.patch("time.time", return_value=now):
        main._update_realized_yield(repo, updater, scanner, pf or FakePriceFetcher(prices))
    return json.loads(repo.files["data/estimated_rewards_usd.json"])


def _files(prev_estimated, tokens_29_oct=(USDC, WETH)):
    epochs = {"epochs": {str(E_22_OCT): {"tokens": [USDC]}, str(E_29_OCT): {"tokens": list(tokens_29_oct)},
                         str(E_05_NOV): {"tokens": [USDC]}}}
    return {"data/epochs.json": json.dumps(epochs),
            "data/yield_history.json": json.dumps(_keeper_history(), indent=2),
            "data/estimated_rewards_usd.json": json.dumps(prev_estimated)}


class RA_GuardLocksAndFreezesSilently(unittest.TestCase):
    """M-A: the 3x guard's reference was min(previous published, previous epoch's history entry). Any LOW value that
    reached the file - a partial-funding day, a transiently unpriced funded token, the 2-week stale 0%, or another
    writer's estimate - became the reference, and every later genuine value above 3x of it was refused, with no flag."""

    def test_transiently_unpriced_token_publishes_a_low_value_then_locks_the_feed(self):
        repo = FakeRepo(_files({"apyPct": 15.1, "epoch": E_22_OCT, "source": "ChainProcessingBot"}))
        up = FakeUpdater(repo)
        rewards = {(USDC, E_29_OCT): 3_000 * 10**6, (WETH, E_29_OCT): 3 * E18}      # $3,000 + 3 WETH ($7,200)
        # day 1: DefiLlama omits WETH and the DEX fallback fails -> WETH unpriced; sanity_problems() passes it
        d1 = _run_bot(repo, up, {USDC: 1.0, WETH: 0.0}, rewards, E_29_OCT + 9060)
        self.assertEqual(d1["unpricedTokens"], [WETH])
        hist = json.loads(repo.files["data/yield_history.json"])
        # adapted: the review asserted latest == 29 Oct here (the low value entering history). The in-progress
        # week is no longer written, so it can't become a reference.
        self.assertNotEqual(hist["latest"]["epoch"], E_29_OCT, "an in-progress, partly priced week entered yield_history")
        # day 2: every price is back; the true figure is 16.9% (1.3x the previous epoch's 12.59%)
        d2 = _run_bot(repo, up, {USDC: 1.0, WETH: 2400.0}, rewards, E_29_OCT + DAY + 9060)
        self.assertGreater(d2["apyPct"], 10.0,
                           f"day 2 still publishes the day-1 figure {d2['apyPct']:.2f}% (WETH unpriced) with no "
                           f"stale flag: the true 16.9% is refused as a >3x jump over that same bad value")

    def test_partial_funding_day_locks_the_guard_for_the_week_and_the_next(self):
        # adapted: the review called the guard directly (merging the partial day into yield_history by hand);
        # here the bot runs the three days itself
        repo = FakeRepo(_files({"apyPct": 15.1, "epoch": E_22_OCT}))
        up = FakeUpdater(repo)
        # Thu 29 Oct: only part of the week's funding has landed -> 4%
        d1 = _run_bot(repo, up, {USDC: 1.0}, {(USDC, E_29_OCT): usdc_for(4.0)}, E_29_OCT + 9060)
        self.assertAlmostEqual(d1["apyPct"], 4.0, places=3)
        # Fri: the rest lands -> 20% (1.6x the last full epoch, 12.59%)
        full = {(USDC, E_29_OCT): usdc_for(20.0)}
        d2 = _run_bot(repo, up, {USDC: 1.0}, full, E_29_OCT + DAY + 9060)
        # next week: a normal 20% week
        d3 = _run_bot(repo, up, {USDC: 1.0}, {**full, (USDC, E_05_NOV): usdc_for(20.0)}, E_05_NOV + 9060)
        self.assertEqual((round(d2["apyPct"], 3), round(d3["apyPct"], 3), d3.get("epoch")), (20.0, 20.0, E_05_NOV),
                         "genuine 20% refused (same week and/or next week)")
        series = json.loads(repo.files["data/yield_history.json"])["series"]
        self.assertEqual([(x["epoch"], round(x["apyPct"], 3)) for x in series if x["epoch"] >= E_29_OCT],
                         [(E_29_OCT, 20.0)], "29 Oct must enter yield_history once, with the full week's funding")

    def test_stale_zero_then_first_aero_funding_keeps_publishing_zero(self):
        # no funding for 2 weeks after the migration -> the bot itself published apyPct 0 (stale=True);
        # the first Aero-era funding gives 40% (live block today projects ~36% from #1584)
        prev = {"apyPct": 0.0, "stale": True, "stakersWeeklyUSD_1e18": "0", "tvlUSD_1e18": str(3_135_570 * E18)}
        repo = FakeRepo(_files(prev))
        d = _run_bot(repo, FakeUpdater(repo), {USDC: 1.0}, {(USDC, E_29_OCT): usdc_for(40.0)}, E_29_OCT + 9060)
        self.assertAlmostEqual(d["apyPct"], 40.0, places=3,
                               msg="refused; TwitterBot/DefiLlama/site keep reading 0% until a manual override")
        self.assertFalse(d["stale"])

    def test_low_positive_estimate_from_another_writer_deadlocks_the_guard(self):
        # any other writer of this file (e.g. the legacy voting keeper estimating from a 600 AERO NFT: ~0.0024%)
        repo = FakeRepo(_files({"apyPct": 0.0024, "source": "EnhancedOptimizedVotesKeeper"}))
        d = _run_bot(repo, FakeUpdater(repo), {USDC: 1.0}, {(USDC, E_29_OCT): usdc_for(15.1)}, E_29_OCT + 9060)
        self.assertAlmostEqual(d["apyPct"], 15.1, places=3,
                               msg="the bot can never replace the keeper's figure again")



class RD_TrustedDexPrice(unittest.TestCase):
    """The new AERO has no DefiLlama price and is ~60-70% of the daily harvester's funding by value. Its DEX price
    counts when its pool is at least DEX_TRUSTED_DEPTH_USD ($1M) deep on its quote side; from a thinner pool it is
    left out of the figures (excludedTokens)."""
    AERO = realized_yield.AERO_ADDRESS.lower()
    PREV = {"apyPct": 15.1, "epoch": E_22_OCT, "updatedAt": "2026-10-28T02:31:00.000Z", "stale": False}

    def _pf(self, usdc_depth):
        ch = FakeChain()
        ch.add_aero_pool(AERO_VOLATILE_FACTORY, AERO_CS, int(usdc_depth / 0.81 * E18), USDC_CS, int(usdc_depth * 10**6))
        with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(ch)):
            pf = price_fetcher.PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"), rpc_url="http://fake",
                                            usdc=USDC_CS, weth=WETH_CS)
        agg = {USDC: 1.0, IAERO: IAERO_PX}            # DefiLlama prices USDC and iAERO, not the new AERO
        pf._fetch_llama = lambda addrs: {a: {"priceUsd": agg[a], "updatedAt": 0, "source": "llama"}
                                         for a in addrs if a in agg}
        pf._fetch_coingecko = lambda addrs: {}
        return pf

    def _run(self, usdc_depth, env=None):
        repo = FakeRepo(_files(self.PREV, tokens_29_oct=(USDC, self.AERO)))
        # $3,000 of USDC + $7,000 of new AERO (70% of the funded value) -> 16.6%
        rewards = {(USDC, E_29_OCT): 3_000 * 10**6, (self.AERO, E_29_OCT): int(7_000 / 0.81 * E18)}
        return _run_bot(repo, FakeUpdater(repo), None, rewards, E_29_OCT + 9060, env=env, pf=self._pf(usdc_depth))

    def test_aero_from_a_6m_pool_is_published(self):
        d = self._run(6_000_000)
        self.assertFalse(d.get("stale"), f"blocked: {d.get('staleReason')}")
        self.assertAlmostEqual(d["apyPct"], 10_000 / STAKED_USD * 52 * 100, places=2)
        (tok,) = d["dexPricedTokens"]
        self.assertEqual((tok["address"], tok["trusted"], tok["poolDepthUsd"]), (self.AERO, True, 6_000_000.0))

    def test_aero_from_a_30k_pool_is_left_out(self):
        # adapted (round 3): this used to keep the previous figures flagged stale; now AERO is left out and listed
        usdc_only = 3_000 / STAKED_USD * 52 * 100
        d = self._run(30_000)
        self.assertFalse(d["stale"])
        self.assertAlmostEqual(d["apyPct"], usdc_only, places=6)
        self.assertEqual([(x["address"], x["reason"]) for x in d["excludedTokens"]], [(self.AERO, "untrusted DEX price")])
        # the threshold is env-overridable: the $6M pool is untrusted under a $10M threshold
        d = self._run(6_000_000, env={"DEX_TRUSTED_DEPTH_USD": "10000000"})
        self.assertAlmostEqual(d["apyPct"], usdc_only, places=6)


if __name__ == "__main__":
    unittest.main()
