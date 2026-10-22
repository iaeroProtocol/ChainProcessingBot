# test_review3_findings.py
# Third independent review of ChainProcessingBot PR #5 at 68baf3a (after 663f1e5 + 68baf3a, the M-A fix):
# R3_1 (H-1, partial-week headline), R3_2 (M-1, ratio check freezes), R3_3 (depth as the only trust test).
# Every test asserts the SAFE behaviour and fails on 68baf3a. R3_1 and R3_3 are adapted to the new design (see
# their comments); the review's R3_4 (a Low) is not here.
# No network. Run: python -m pytest -p no:pytest_ethereum -q tests/test_review3_findings.py
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
from realized_yield import WEEK, epoch_start  # noqa: E402
from test_realized_yield import FakeDistributorWeb3, _keeper_history  # noqa: E402
from test_review2_findings import FakeRepo, FakeUpdater  # noqa: E402
from test_price_fetcher import FakeChain, fake_web3_cls, AERO_VOLATILE_FACTORY  # noqa: E402
from test_price_fetcher import USDC as USDC_CS, WETH as WETH_CS  # noqa: E402

E18 = 10 ** 18
DAY = 86400
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
IAERO = "0x81034fb34009115f215f5d5f564aac9ffa46a1dc"
AERO = realized_yield.AERO_ADDRESS.lower()
X = "0x00000000000000000000000000000000000a11ce"     # a funded token DefiLlama doesn't price (fee / bribe token)
E_22_OCT = 1792627200
E_29_OCT = E_22_OCT + WEEK
RUN = 2 * 3600 + 31 * 60          # ChainProcessingBot cron, ~02:31 UTC
HARVEST = 6 * 3600                # aero-rewards-harvester config/mainnet.json runTimeUtc "06:00"
STAKED_RAW = 4_710_927 * E18      # staked iAERO at epoch start (live)
IAERO_PX = 0.6656
STAKED_USD = 4_710_927 * IAERO_PX
EP = "data/estimated_rewards_usd.json"
YH = "data/yield_history.json"


def weekly_usd_for(apy: float) -> float:
    return apy / 100 / 52 * STAKED_USD


class PF:
    """fetch_batch like PriceFetcher's: llama prices, or DEX prices with the pool's quote-side depth."""

    def __init__(self, llama, dex=None):
        self.llama, self.dex = llama, dex or {}

    def fetch_batch(self, addrs):
        out = {}
        for a in addrs:
            if a in self.llama:
                out[a] = {"priceUsd": self.llama[a], "source": "llama"}
            elif a in self.dex:
                px, depth = self.dex[a]
                out[a] = {"priceUsd": px, "source": "dex", "dexDepthUsd": depth}
            else:
                out[a] = {"priceUsd": 0.0, "source": "none"}
        return out


LLAMA = {USDC: 1.0, IAERO: IAERO_PX, AERO: 0.81}


def run_bot(repo, rewards, now, pf, env=None, events=None):
    """One cron run of main._update_realized_yield against an in-memory repo; epochs.json is derived from `rewards`
    (as _update_epochs would have scanned it). Adapted: `events` (RewardFunded with block time) answer the scanner's
    reward_funded_events() for the rolling mode."""
    epochs = {}
    for (tok, ep), amt in rewards.items():
        if amt > 0 and ep <= epoch_start(now):
            epochs.setdefault(str(ep), {"tokens": []})["tokens"].append(tok)
    repo.files["data/epochs.json"] = json.dumps({"epochs": epochs})
    w3 = FakeDistributorWeb3(rewards=rewards, snapshot={E_22_OCT + k * WEEK: STAKED_RAW for k in range(-4, 12)},
                             supply_at_start={}, total_staked=STAKED_RAW)
    scanner = mock.Mock(w3=w3)
    scanner.decimals_map.side_effect = lambda toks, **k: {USDC: 6, X: 18}
    scanner.reward_funded_events.side_effect = lambda dist, frm, to: [e for e in events or [] if frm <= e["timestamp"] <= to]
    e = {"EPOCH_STAKING_DISTRIBUTOR": DIST, "LIVE_YIELD_ENABLED": "false", "YIELD_HISTORY_ENABLED": "true"}
    e.update(env or {})
    with mock.patch.dict(os.environ, e), mock.patch("time.time", return_value=now):
        main._update_realized_yield(repo, FakeUpdater(repo), scanner, pf)
    return json.loads(repo.files[EP])


def daily_harvest_events(now, per_day, start=E_22_OCT, until=None):
    """The same daily fundings as RewardFunded events with their block time (adapted for the rolling mode)."""
    out, ts = [], start + HARVEST
    while ts < now and (until is None or ts < until):
        for tok, amt in per_day(epoch_start(ts)).items():
            out.append({"token": tok, "epoch": epoch_start(ts), "amount": amt, "timestamp": ts, "blockNumber": ts // 2})
        ts += DAY
    return out


def daily_harvests(now, per_day, start=E_22_OCT, until=None):
    """rewardsForEpoch as of `now` when the harvester funds `per_day` {token: raw} every day at 06:00 into the
    CURRENT epoch (RewardsHarvesterV2.processAndDistribute -> notifyRewardAmount -> currentEpoch())."""
    rewards = {}
    ts = start + HARVEST
    while ts < now and (until is None or ts < until):
        ep = epoch_start(ts)
        for tok, amt in per_day(ep).items():
            rewards[(tok, ep)] = rewards.get((tok, ep), 0) + amt
        ts += DAY
    return rewards


# ------------------------------------------------------------------------------------------------------------------
class R3_1_PartialWeekHeadline(unittest.TestCase):
    """ESTIMATED_REWARDS_EPOCH defaults to latest_funded: as soon as the running epoch has ANY funding it is the one
    published. The daily harvester funds the running epoch every day at 06:00, after the 02:31 run, so Fri..Wed
    publish 1/7..6/7 of the week's realized yield as an annual APY (DefiLlama apyBase, TwitterBot's 14:00 tweet, and
    the site's stakersWeeklyUSD_1e18 x 52 / TVL)."""

    def test_published_apy_tracks_the_weekly_rate_every_day(self):
        # adapted: the fix is the rolling mode, switched on by ROLLING_SINCE_TS (the harvester's first run), reading
        # the RewardFunded events
        per_day = lambda ep: {USDC: round(weekly_usd_for(15.0) / 7 * 10 ** 6)}      # a steady 15% APY
        repo = FakeRepo({EP: json.dumps({"apyPct": 15.1, "epoch": E_22_OCT}), YH: json.dumps(_keeper_history())})
        got = []
        for d in range(8):                                   # Thu 29 Oct .. Thu 5 Nov, 02:31 UTC
            now = E_29_OCT + d * DAY + RUN
            out = run_bot(repo, daily_harvests(now, per_day), now, PF(LLAMA),
                          env={"ROLLING_SINCE_TS": str(E_22_OCT + HARVEST)}, events=daily_harvest_events(now, per_day))
            got.append((("Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed")[d % 7], round(out["apyPct"], 2),
                        round(int(out["stakersWeeklyUSD_1e18"]) / E18)))
        bad = [g for g in got if not 11.25 <= g[1] <= 18.75]
        self.assertFalse(bad, f"true rate 15% (${weekly_usd_for(15.0):,.0f}/week) every day; published "
                                  f"(day, apyPct, stakersWeeklyUSD): {got}")


# ------------------------------------------------------------------------------------------------------------------
REAL_HISTORY = {     # newest live yield_history.json entries (keeper-written), 22 Oct 2026
    "updatedAt": "2026-10-22T00:01:48.938Z",
    "latest": {"epoch": E_22_OCT, "apyPct": 12.589882348027016, "tvlUSD_1e18": "1", "stakersWeeklyUSD_1e18": "1"},
    "series": [{"epoch": e, "timestamp": e + 100, "apyPct": a, "tvlUSD_1e18": "1", "stakersWeeklyUSD_1e18": "1"}
               for e, a in ((1790208000, 12.034), (1790812800, 17.367), (1791417600, 11.266),
                            (1792022400, 10.302), (E_22_OCT, 12.589882348027016))],
}


class R3_2_RegimeShiftFreeze(unittest.TestCase):
    """Reference for 29 Oct = median(17.37, 11.27, 10.30, 12.59) = 11.93 -> 3x limit 35.78%. Today's live block
    projects 36.66% for #1584, i.e. the Aero-era realized APY sits above the Aerodrome-era limit on its own. The
    ratio check then blocks whenever ANY untrusted DEX-priced token pulls `apy without DEX` under 35.78% - here 3%
    of the funding. A blocked completed epoch is never written to yield_history, so the reference never moves and
    the feed stays stale until someone sets APY_MAX_RISE=0 (which also turns the >50% check off)."""

    def _per_day(self, x_share):
        def per_day(ep):
            if ep < E_29_OCT:                                # last Aerodrome-era funding: 15%, USDC only
                return {USDC: round(weekly_usd_for(15.0) / 7 * 10 ** 6)}
            wk = weekly_usd_for(36.66) / 7                    # Aero era: the live block's projection
            return {USDC: round(wk * (1 - x_share) * 10 ** 6), X: round(wk * x_share / 2.0 * E18)}
        return per_day

    def _weeks(self, x_share):
        repo = FakeRepo({EP: json.dumps({"apyPct": 15.1, "epoch": E_22_OCT}), YH: json.dumps(REAL_HISTORY)})
        pf = PF(LLAMA, dex={X: (2.0, 200_000.0)})            # X: $2 from a pool with $200k of USDC -> untrusted
        days = []
        for d in range(29):                                  # 29 Oct .. 26 Nov
            now = E_29_OCT + d * DAY + RUN
            # the R3_1 fix applied (headline = last completed week), so the partial-week issue doesn't mask this
            out = run_bot(repo, daily_harvests(now, self._per_day(x_share)), now, pf,
                          env={"ESTIMATED_REWARDS_EPOCH": "last_completed"})
            days.append((d, out.get("stale"), round(out["apyPct"], 2), out.get("updatedAt")))
        hist = [(x["epoch"], round(x["apyPct"], 2)) for x in json.loads(repo.files[YH])["series"] if x["epoch"] >= E_29_OCT]
        return days, hist

    def test_aero_era_yield_with_a_small_untrusted_token_freezes_the_feed(self):
        days, hist = self._weeks(0.0)                        # control: no DEX-priced token -> published, recorded
        self.assertFalse(any(s for _, s, _, _ in days))
        self.assertEqual(hist[0], (E_29_OCT, 36.66))
        days, hist = self._weeks(0.03)                       # 3% of the funding in X
        stale_days = [d for d, s, _, _ in days if s]
        # adapted: the message indexed stale_days[0], which raised when there were none (the safe outcome)
        self.assertTrue(not stale_days and hist,
                        f"stale on days {stale_days[:1]}..{stale_days[-1:]} of 28 (still stale on 26 Nov, apyPct "
                        f"{days[-1][2]}%, updatedAt {days[-1][3]} -> TwitterBot/DefiLlama dropped the APY 8 days "
                        f"later); yield_history Aero-era entries: {hist}. The true 36.66% (35.56% without X) is "
                        f"never published, and nothing but APY_MAX_RISE=0 ends it")


# ------------------------------------------------------------------------------------------------------------------
class R3_3_DepthIsTheOnlyTrustTest(unittest.TestCase):
    """68baf3a: a DEX price is 'trusted' (exempt from both checks) when its pool's quote side holds >= $1M. Depth is
    the only test: a v2 pool seeded by one LP with $1.2M of USDC against a few tokens prices the token at whatever
    ratio the LP chose, and the guard waves it through up to the 500% sanity cap."""

    def test_single_lp_deep_pool_sets_any_price(self):
        ch = FakeChain()
        tok = price_fetcher.Web3.to_checksum_address(X)
        ch.decimals[tok] = 18
        ch.add_aero_pool(AERO_VOLATILE_FACTORY, tok, 1_000 * E18, USDC_CS, 1_200_000 * 10 ** 6)   # "$1,200 / token"
        with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(ch)):
            pf = price_fetcher.PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"), rpc_url="http://x",
                                            usdc=USDC_CS, weth=WETH_CS)
        pf._fetch_llama = lambda addrs: {a: {"priceUsd": LLAMA[a], "updatedAt": 0, "source": "llama"}
                                         for a in addrs if a in LLAMA}
        pf._fetch_coingecko = lambda addrs: {}
        # a normal 15% week in USDC plus 60 X (fair value ~$2 each) that the pool prices at ~$1,200
        rewards = {(USDC, E_29_OCT): round(weekly_usd_for(15.0) * 10 ** 6), (X, E_29_OCT): 60 * E18}
        repo = FakeRepo({EP: json.dumps({"apyPct": 15.1, "epoch": E_22_OCT}), YH: json.dumps(REAL_HISTORY)})
        out = run_bot(repo, rewards, E_29_OCT + RUN, pf)
        # adapted: the review asserted the guard kept the figures stale; the new design leaves X out instead (it is
        # not in TRUSTED_DEX_TOKENS), publishes the USDC 15%, and never goes stale over DEX prices
        self.assertAlmostEqual(out["apyPct"], 15.0, places=3,
                               msg=f"published apyPct {out['apyPct']:.1f}%; X counted as {out.get('dexPricedTokens')}")
        self.assertFalse(out.get("stale"))
        self.assertEqual([(x["address"], x["reason"]) for x in out["excludedTokens"]], [(X, "untrusted DEX price")])


if __name__ == "__main__":
    unittest.main()
