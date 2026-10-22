# test_measured_headline.py
# The headline APY from #1584's MEASURED earnings (owner decision after review 7). Unit tests for
# realized_yield.measured_headline / apply_measured / kept_headline, and main._update_realized_yield end to end
# against a simulated world: Base, Ethereum and Robinhood (4663), one gauge each whose VRM accrues fees and an
# incentive at constant rates from #1584's first allocation, the harvester's claims as ClaimFees / ClaimIncentives
# logs, block-pinned reads (Robinhood: 0.1 s blocks), distributor fundings on any schedule, an in-memory GitHub repo.
# No network. Run: python -m pytest -p no:pytest_ethereum -q tests/test_measured_headline.py
import base64
import json
import math
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from web3 import Web3  # noqa: E402

import main  # noqa: E402
import position_earnings as pe  # noqa: E402
import price_fetcher  # noqa: E402
import realized_yield as ry  # noqa: E402
from test_realized_yield import FakeDistributorWeb3, _keeper_history, LEGACY_KEYS  # noqa: E402

E18 = 10 ** 18
DAY = 86400
WEEK = 7 * DAY
DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
T0 = pe.FIRST_ALLOCATION[1584]                 # 22 Oct 2026 02:11:03 UTC
E22 = 1792627200                               # epoch 22 Oct (Thursday 00:00 UTC)
RUN0 = E22 + 9060                              # the daily run, 02:31 UTC; day d runs at RUN0 + d * DAY
GENESIS = RUN0 - 30 * DAY                      # block 0 (runs fall on block times on every chain)
EST, YH, LS = "data/estimated_rewards_usd.json", "data/yield_history.json", "data/live_state.json"

AERO, IAERO = ry.AERO_ADDRESS.lower(), ry.IAERO_ADDRESS.lower()
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
WETH = "0x4200000000000000000000000000000000000006"
ETH_WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
ETH_USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
RH_WETH, RH_USDG = sorted(pe.ROBINHOOD_PRICE_MAP)            # 0x0bd7... WETH, 0x5fc5... USDG
DEC = {WETH: 18, USDC: 6, AERO: 18, ETH_WETH: 18, ETH_USDT: 6, RH_WETH: 18, RH_USDG: 6}
SYM = {WETH: "WETH", USDC: "USDC", AERO: "AERO", ETH_WETH: "WETH", ETH_USDT: "USDT", RH_WETH: "WETH", RH_USDG: "USDG"}
PRICES = {8453: {WETH: 4000.0, USDC: 1.0, AERO: 0.8, IAERO: 0.66}, 1: {ETH_WETH: 4000.0, ETH_USDT: 1.0},
          4663: {RH_WETH: 4000.0, RH_USDG: 1.0}}
STAKED_RAW = 4_000_000 * E18                   # staked iAERO at every epoch start
STAKED_USD = 4_000_000 * 0.66                  # the apyPct denominator
STAKE_AERO = 4_853_405 * E18
# raw per second: token0 fees, token1 fees, incentive (program 1)
RATES = {8453: (WETH, 1_157_407_407_407, USDC, 1_157, AERO, 5_787_037_037_037_037),    # $400 + $100 + $400 a day
         1: (ETH_WETH, 115_740_740_741, ETH_USDT, 116, ETH_USDT, 58),                  # $40 + $10 + $5
         4663: (RH_WETH, 231_481_481_481, RH_USDG, 232, RH_WETH, 115_740_740_741)}     # $80 + $20 + $40
BLOCK_TIME = {8453: 2.0, 1: 12.0, 4663: 0.1}


def usd_per_day(chains=(8453, 1, 4663), leave_out=()):
    out = 0.0
    for cid in chains:
        t0, r0, t1, r1, inc, ri = RATES[cid]
        for tok, r in ((t0, r0), (t1, r1), (inc, ri)):
            if (cid, tok) not in leave_out:
                out += r * DAY / 10 ** DEC[tok] * PRICES[cid][tok]
    return out


TRUE_APY = usd_per_day() * 365 * 0.8 / STAKED_USD * 100          # ~ 15.9%


def _addr(byte: str, cid: int) -> str:
    return "0x" + byte * 16 + format(cid, "08x")


class SimChain:
    """One chain as #1584 sees it: one gauge whose VRM accrues token0/token1 fees and incentive program 1 at constant
    raw-per-second rates from T0. harvest(ts) claims everything unclaimed (ClaimFees / ClaimIncentives logs)."""

    def __init__(self, cid):
        self.cid, self.bt = cid, BLOCK_TIME[cid]
        self.t0, self.r0, self.t1, self.r1, self.inc, self.ri = RATES[cid]
        self.gauge, self.vrm, self.pool = _addr("a1", cid), _addr("b1", cid), _addr("c1", cid)
        self.claims = []                       # (block, kind, token, amount)
        self.logs_down, self.log_calls = False, []

    def block_of(self, ts):
        return int(round((ts - GENESIS) / self.bt, 6))

    def ts_of(self, b):
        return GENESIS + int(b * self.bt)

    def accrued(self, ts):
        e = max(0, int(ts) - T0)
        return {("fee", self.t0): self.r0 * e, ("fee", self.t1): self.r1 * e, ("inc", self.inc): self.ri * e}

    def claimed(self, block):
        out = {}
        for b, kind, tok, amt in self.claims:
            if b <= block:
                out[(kind, tok)] = out.get((kind, tok), 0) + amt
        return out

    def harvest(self, ts):
        b = self.block_of(ts)
        acc, cl = self.accrued(self.ts_of(b)), self.claimed(b)
        for key, a in acc.items():
            if a - cl.get(key, 0) > 0:
                self.claims.append((b, key[0], key[1], a - cl.get(key, 0)))

    def log(self, b, kind, tok, amt):
        tid = (1584).to_bytes(32, "big")
        if kind == "fee":
            topics = [bytes.fromhex(pe.CLAIM_FEES_TOPIC[2:]), tid, bytes(32), bytes(12) + bytes.fromhex(tok[2:])]
        else:
            topics = [bytes.fromhex(pe.CLAIM_INCENTIVES_TOPIC[2:]), tid, bytes(32), (1).to_bytes(32, "big")]
        return {"address": Web3.to_checksum_address(self.vrm), "topics": topics, "data": amt.to_bytes(32, "big"),
                "blockNumber": b}


class SimReader:
    """ChainReader over a SimChain at time `now` (block-pinned like the real one)."""

    def __init__(self, sim, now):
        self.sim, self.chain_id = sim, sim.cid
        self.block = sim.block_of(now)
        self.block_ts = sim.ts_of(self.block)

    def many(self, calls):
        return [self._one((t or "").lower(), sig, list(args)) for t, sig, args, _ in calls]

    def _one(self, target, sig, args=None):
        """Answers for the sim's own gauge / VRM / pool only (another target: the call fails, None)."""
        s = self.sim
        acc, cl = s.accrued(self.block_ts), s.claimed(self.block)
        left = lambda k: acc[k] - cl.get(k, 0)
        own = {"votingRewardsManager()": s.gauge, "pool()": s.gauge, "tickSpacing()": s.pool, "gauge()": s.vrm,
               "token0()": s.vrm, "token1()": s.vrm, "earnedFees(uint256,uint256)": s.vrm, "incentiveCount()": s.vrm,
               "incentive(uint256)": s.vrm, "earnedIncentives(uint256,uint256,uint256)": s.vrm}
        if sig in own and target != own[sig]:
            return None
        if sig in ("gaugeToRewards(address)", "allocations(uint256,address)", "gaugeStates(address)") \
                and args is not None and str(args[-1]).lower() != s.gauge:
            return None
        return {
            "allocatedGauges(uint256)": [Web3.to_checksum_address(s.gauge)],
            "tokenStates(uint256)": (pe.ZERO, T0, False, 1_000_000 * E18),
            "allocations(uint256,address)": 1_000_000 * E18,
            "votingRewardsManager()": s.vrm, "gaugeToRewards(address)": s.vrm, "pool()": s.pool, "gauge()": s.gauge,
            "gaugeStates(address)": (0, 0, 0, True, True, 0, 0, 0, 0, 0, 0, 0),
            "token0()": s.t0, "token1()": s.t1,
            "earnedFees(uint256,uint256)": (left(("fee", s.t0)), left(("fee", s.t1))),
            "incentiveCount()": 1, "tickSpacing()": 100,
            "incentive(uint256)": (s.inc, 0, 0, T0, T0 + 400 * DAY, pe.ZERO),
            "earnedIncentives(uint256,uint256,uint256)": left(("inc", s.inc)),
            "balanceOfNFT(uint256)": STAKE_AERO,
            "symbol()": SYM.get(target), "decimals()": DEC.get(target),
        }.get(sig)

    def block_at(self, ts):
        return max(0, min(self.block, self.sim.block_of(ts)))

    def logs(self, addresses, topics, from_block, to_block=None, **kw):
        """addresses None: any contract (the discovery scan); the sim's claims all come from its VRM."""
        self.sim.log_calls.append(int(from_block))
        if self.sim.logs_down:
            return None
        addrs = None if addresses is None else {a.lower() for a in addresses}
        tb = self.block if to_block is None else min(to_block, self.block)
        return [self.sim.log(b, k, t, a) for b, k, t, a in self.sim.claims
                if from_block <= b <= tb and (addrs is None or self.sim.vrm in addrs)]


class AnyEpoch(dict):
    def __init__(self, v):
        super().__init__()
        self.v = v

    def get(self, k, d=None):
        return self.v


class _F:
    def __init__(self, text):
        self.content = base64.b64encode(text.encode()).decode()


class FakeRepo:
    def __init__(self, files):
        self.files = dict(files)
        self.fail = {}                          # path -> exception on read

    def get_contents(self, path, ref=None):
        if path in self.fail:
            raise self.fail[path]
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


class FakePF:
    """fetch_batch from a {token: price} table; `dex` {token: pool depth} marks a price as the DEX fallback's."""

    def __init__(self, prices, dex=None):
        self.prices, self.dex = prices, dex or {}

    def fetch_batch(self, addrs):
        return {a: {"priceUsd": self.prices.get(a, 0.0),
                    "source": "dex" if a in self.dex else ("llama" if self.prices.get(a) else "none"),
                    **({"dexDepthUsd": self.dex[a]} if a in self.dex else {})} for a in addrs}


def previous_headline():
    """estimated_rewards_usd.json as the funding-based design last published it (a full legacy document)."""
    p = ry.compute_realized(E22, [{"address": USDC, "amount": 9_265 * 10 ** 6, "decimals": 6, "priceUsd": 1.0}],
                            3_826_910 * E18, 3_826_910 * E18, iaero_price=0.66, aero_price=0.8, distributor=DIST,
                            now_ts=E22 + 108)
    return p


class World:
    """Runs main._update_realized_yield day by day against the simulated chains."""

    def __init__(self, harvests=(), fundings=(), prev=None, chain_prices=None, base_pf=None, llama=None,
                 first_gauges=None):
        self.sims = {cid: SimChain(cid) for cid in (8453, 1, 4663)}
        self.harvests = sorted(harvests)                     # [(ts, chainId)]
        self.fundings = list(fundings)                       # [(ts, raw USDC)] into the distributor
        files = {YH: json.dumps(_keeper_history(), indent=2)}
        if prev is not False:
            files[EST] = json.dumps(prev or previous_headline())
        self.repo = FakeRepo(files)
        self.updater = FakeUpdater(self.repo)
        self.chain_prices = chain_prices or {1: FakePF(PRICES[1]), 4663: FakePF(PRICES[4663])}
        self.base_pf = base_pf or FakePF(PRICES[8453])
        self.llama = llama or {}                             # DefiLlama by key, for MappedPriceFetcher's lookups
        self.first_gauges = first_gauges or {}               # more first-allocation gauges for the config {cid: [g]}

    def run(self, now, env=None, unreachable=(), live_error=None):
        while self.harvests and self.harvests[0][0] <= now:
            ts, cid = self.harvests.pop(0)
            self.sims[cid].harvest(ts)
        rewards = {}
        for ts, amt in self.fundings:
            if ts <= now:
                key = (USDC, ts // WEEK * WEEK)
                rewards[key] = rewards.get(key, 0) + amt
        self.repo.files["data/epochs.json"] = json.dumps({"epochs": {str(ep): {"tokens": [USDC]} for _, ep in rewards}})
        w3 = FakeDistributorWeb3(rewards=rewards, snapshot=AnyEpoch(STAKED_RAW), supply_at_start={},
                                 total_staked=STAKED_RAW)
        scanner = mock.Mock(w3=w3)
        scanner.decimals_map.side_effect = lambda toks, **k: {USDC: 6}
        down = {{1: "https://ethereum-rpc.publicnode.com", 4663: pe.ROBINHOOD_RPC}[c] for c in unreachable}

        class FakeWeb3:
            @staticmethod
            def HTTPProvider(url, request_kwargs=None):
                return url

            def __init__(self, url):
                if url in down:
                    raise ConnectionError(f"{url} unreachable")
                self.eth = mock.Mock(block_number=10 ** 9)

        slug = {"ethereum": 1, "robinhood": 4663}
        e = {"EPOCH_STAKING_DISTRIBUTOR": DIST}
        e.update(env or {})
        live_patch = (mock.patch.object(main, "_build_live_block", side_effect=live_error) if live_error
                      else mock.patch.object(main, "_stake_accrual_start", wraps=main._stake_accrual_start))
        # the config's first-allocation gauges are this world's gauges (#1584's real ones don't exist here)
        seed = {1584: {cid: [s.gauge] + list(self.first_gauges.get(cid, [])) for cid, s in self.sims.items()}}
        with mock.patch.dict(os.environ, e), mock.patch("time.time", return_value=now), \
             mock.patch.object(pe, "FIRST_ALLOCATION_GAUGES", seed), \
             mock.patch.object(pe, "ChainReader", side_effect=lambda w3_, cid, block=None, **k: SimReader(self.sims[cid], now)), \
             mock.patch("web3.Web3", FakeWeb3), \
             mock.patch.object(main, "PriceFetcher", side_effect=lambda chain_slug="base", **k: self.chain_prices[slug[chain_slug]]), \
             mock.patch.object(price_fetcher, "llama_prices",
                               side_effect=lambda keys, **k: {x: self.llama[x] for x in keys if x in self.llama}), \
             live_patch:
            for k in ("ETH_RPC_URL", "ROBINHOOD_RPC_URL", "PROTOCOL_AERO_STAKE_SINCE", "PROTOCOL_AERO_STAKE_ID",
                      "TRUSTED_DEX_TOKENS", "DEX_TRUSTED_DEPTH_USD", "ESTIMATED_REWARDS_ENABLED", "YIELD_HISTORY_ENABLED"):
                if k not in (env or {}):
                    os.environ.pop(k, None)
            main._update_realized_yield(self.repo, self.updater, scanner, self.base_pf)
        return json.loads(self.repo.files[EST]) if EST in self.repo.files else None

    def days(self, n, start=0, hook=None):
        out = []
        for d in range(start, start + n):
            if hook:
                hook(self, d)
            out.append(self.run(RUN0 + d * DAY))
        return out


def daily_harvests(first_day=1, last_day=24, skip=()):
    """The harvester claims on every chain at 00:05 UTC each day."""
    return [(E22 + d * DAY + 300, cid) for d in range(first_day, last_day + 1) if d not in skip for cid in (8453, 1, 4663)]


def daily_fundings(first_day=1, last_day=24, scale=None):
    """The distributor gets the stakers' 80% of the previous day's earnings in USDC at 00:10 UTC each day."""
    day_usdc = round(usd_per_day() * 0.8 * 10 ** 6)
    return [(E22 + d * DAY + 600, round(day_usdc * (scale or {}).get(d, 1.0))) for d in range(first_day, last_day + 1)
            if (scale or {}).get(d, 1.0) > 0]


# ---------------- unit tests: realized_yield ----------------
def _live(**kw):
    live = {"stale": False, "asOf": RUN0 + 8 * DAY, "since": T0, "elapsedDays": 6.0, "readComplete": True,
            "usdPerDay": 1_000.0, "trailing": {"7d": {"complete": True, "partial": False, "usdPerDay": 900.0,
                                                      "snapshotAsOf": RUN0 + DAY}}}
    live.update(kw)
    return live


class MeasuredHeadlineTest(unittest.TestCase):
    def test_complete_7d_window_is_used(self):
        rate, src, win = ry.measured_headline(_live())
        self.assertEqual((rate, src), (900.0, "measured-7d"))
        self.assertEqual(win, {"from": RUN0 + DAY, "to": RUN0 + 8 * DAY, "days": 7.0})

    def test_incomplete_or_missing_7d_falls_back_to_since_allocation(self):
        for t7 in ({"complete": False, "partial": True, "usdPerDay": 5.0, "snapshotAsOf": RUN0},
                   {"complete": False, "partial": False, "usdPerDay": 5.0, "snapshotAsOf": RUN0}, None):
            rate, src, win = ry.measured_headline(_live(trailing={"7d": t7}))
            self.assertEqual((rate, src), (1_000.0, "measured-since-allocation"))
            self.assertEqual(win, {"from": T0, "to": RUN0 + 8 * DAY, "days": 6.0})
            # review 8 M-1: after week 1 the lifetime average (front-loaded) is never used; the headline is kept
            self.assertIsNone(ry.measured_headline(_live(trailing={"7d": t7}, elapsedDays=7.0)))
            self.assertIsNone(ry.measured_headline(_live(trailing={"7d": t7}, elapsedDays=30.0)))

    def test_otherwise_nothing_never_a_zero(self):
        no7 = {"trailing": {"7d": None}}
        self.assertIsNone(ry.measured_headline(_live(elapsedDays=0.9, **no7)))           # under a day
        self.assertIsNone(ry.measured_headline(_live(readComplete=False, **no7)))       # current read incomplete
        self.assertIsNone(ry.measured_headline(_live(usdPerDay=float("nan"), **no7)))
        self.assertIsNone(ry.measured_headline(_live(stale=True)))                      # previous block kept
        self.assertIsNone(ry.measured_headline(None))

    def test_reason_names_what_is_missing(self):
        r = ry.measured_unavailable_reason(
            _live(readComplete=False, unmeasuredChains=[4663], unpricedTokens=["4663:" + RH_USDG],
                  chains=[{"chainId": 1, "claimsScanned": False, "gaugeListRead": True, "unreadGauges": []}],
                  trailing={"7d": None}))
        for part in ("no 7-day window", "chains not read [4663]", "claims not scanned on 1", "unpriced"):
            self.assertIn(part, r)
        self.assertIn("under 1 day", ry.measured_unavailable_reason(_live(elapsedDays=0.2, trailing={"7d": None})))
        late = ry.measured_unavailable_reason(_live(elapsedDays=9.0, readComplete=False, unmeasuredChains=[1],
                                                    trailing={"7d": None}))
        self.assertIn("not used after 7 days", late)
        self.assertIn("chains not read [1]", late)
        self.assertIn("failed", ry.measured_unavailable_reason(_live(stale=True)))


class ApplyMeasuredTest(unittest.TestCase):
    def base(self, staked_raw=STAKED_RAW):
        return ry.compute_realized(E22 + WEEK, [], staked_raw, staked_raw, iaero_price=0.66, aero_price=0.8,
                                   distributor=DIST, now_ts=RUN0 + 8 * DAY, epoch_mode="measured")

    def test_formulas_and_legacy_fields(self):
        p = ry.apply_measured(self.base(), 1_000.0, "measured-7d", {"from": 1, "to": 2, "days": 7.0}, now_ts=RUN0)
        self.assertAlmostEqual(p["apyPct"], 1_000 * 365 * 0.8 / STAKED_USD * 100, places=10)
        self.assertEqual(p["stakersWeeklyUSD_1e18"], str(5_600 * E18))                 # usdPerDay x 7 x 0.8
        self.assertEqual(p["estimatedWeeklyUSD_1e18"], str(7_000 * E18))               # the gross
        self.assertEqual((p["protocolWeeklyUSD_1e18"], p["pegWeeklyUSD_1e18"]), (str(700 * E18), str(700 * E18)))
        self.assertEqual(p["estimatedAnnualUSD_1e18"], str(7_000 * 52 * E18))
        self.assertEqual((p["apySource"], p["apyWindow"], p["method"], p["stale"]),
                         ("measured-7d", {"from": 1, "to": 2, "days": 7.0}, "measured", False))
        self.assertTrue(LEGACY_KEYS <= set(p))
        for k in LEGACY_KEYS:                                   # same types as the legacy file
            self.assertIsInstance(p[k], type(self.base()[k]), k)
        for k in ("fundedUSD_1e18", "fundedTokenCount", "unpricedTokens", "epochSelection", "staleReason"):
            self.assertNotIn(k, p)                              # funding fields only live under fundedRealized
        self.assertEqual(p["stakedUSD_1e18"], str(2_640_000 * E18))
        self.assertEqual(ry.sanity_problems(p), [])

    def test_no_stake_is_not_a_zero_apy(self):
        p = ry.apply_measured(self.base(staked_raw=0), 1_000.0, "measured-7d", {}, now_ts=RUN0)
        self.assertTrue(math.isnan(p["apyPct"]))
        self.assertTrue(ry.sanity_problems(p))

    def test_kept_headline(self):
        prev = dict(previous_headline(), live={"x": 1}, fundedRealized={"y": 2}, lastUpdated="X", updateTimestamp=0)
        k = ry.kept_headline(prev, "why")
        self.assertEqual((k["apySource"], k["stale"], k["staleReason"]), ("kept", True, "why"))
        self.assertEqual({x: k[x] for x in LEGACY_KEYS}, {x: prev[x] for x in LEGACY_KEYS})   # updatedAt too
        for x in ("live", "fundedRealized", "lastUpdated", "updateTimestamp"):
            self.assertNotIn(x, k)
        self.assertIsNone(ry.kept_headline({}, "why"))
        self.assertIsNone(ry.kept_headline({"apyPct": None}, "why"))


class MeasuredYieldHistoryTest(unittest.TestCase):
    def payload(self, epoch, apy):
        return {"epoch": epoch, "apyPct": apy, "stakedUSD_1e18": "1", "stakersWeeklyUSD_1e18": "2", "method": "measured"}

    def test_measured_entry_written_once_keeper_entries_untouched(self):
        e29 = E22 + WEEK
        doc, why = ry.merge_yield_history(_keeper_history(), self.payload(e29, 15.0), e29 + WEEK)
        self.assertIn("appended measured", why)
        self.assertEqual(doc["series"][:-1], _keeper_history()["series"])
        self.assertEqual(doc["series"][-1]["method"], "measured")
        self.assertIsNone(ry.merge_yield_history(doc, self.payload(e29, 16.0), e29 + WEEK + DAY)[0])     # frozen
        self.assertIsNone(ry.merge_yield_history(_keeper_history(), self.payload(E22, 15.0), e29)[0])   # keeper's
        # a funding-based ("realized") entry of ours is replaced
        realized = dict(doc, series=doc["series"][:-1] + [dict(doc["series"][-1], method="realized")])
        doc2, why = ry.merge_yield_history(realized, self.payload(e29, 16.0), e29 + WEEK)
        self.assertIn("updated measured", why)


class ClaimsStateDueTest(unittest.TestCase):
    def st(self, block_ts=1000, vrms=None):
        return {"stakeId": 1584, "chains": {"8453": {"since": T0, "block": 5, "blockTimestamp": block_ts,
                                                      "vrms": vrms or {}}}}

    def test_rewritten_on_change_or_after_an_hour(self):
        self.assertTrue(main._claims_state_due({}, self.st()))
        self.assertFalse(main._claims_state_due(self.st(), self.st(block_ts=1000 + 3599)))
        self.assertTrue(main._claims_state_due(self.st(), self.st(block_ts=1000 + 3600)))
        self.assertTrue(main._claims_state_due(self.st(), self.st(vrms={"0xv": {"fees": {"0xt": 1}, "incentives": {}}})))
        self.assertFalse(main._claims_state_due(self.st(), None))
        self.assertFalse(main._claims_state_due(self.st(), {"stakeId": 1584, "chains": {}}))


# ---------------- main end to end on the simulated chains ----------------
class MainMeasuredTest(unittest.TestCase):
    def test_first_runs_kept_then_since_allocation_then_7d(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        docs = w.days(9)
        prev = previous_headline()
        # day 0 (20 minutes after the first allocation): the previous headline is kept, flagged
        self.assertEqual((docs[0]["apySource"], docs[0]["apyPct"], docs[0]["updatedAt"]),
                         ("kept", prev["apyPct"], prev["updatedAt"]))
        self.assertIn("under 1 day", docs[0]["staleReason"])
        self.assertTrue(docs[0]["live"]["readComplete"])
        for d in range(1, 6):
            self.assertEqual(docs[d]["apySource"], "measured-since-allocation", d)
            self.assertAlmostEqual(docs[d]["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-6)
            self.assertNotIn("staleReason", docs[d])
        # the trailing 7d window: the history point 6-8 days old closest to 7 days (day 6: the day-0 point)
        for d in (6, 7, 8):
            self.assertEqual(docs[d]["apySource"], "measured-7d", d)
            self.assertAlmostEqual(docs[d]["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5)
            self.assertEqual(docs[d]["apyWindow"], {"from": RUN0 + (0 if d == 6 else d - 7) * DAY, "to": RUN0 + d * DAY,
                                                    "days": 6.0 if d == 6 else 7.0})
        d = docs[8]
        self.assertAlmostEqual(d["measuredUsdPerDay"], usd_per_day(), delta=usd_per_day() * 1e-5)
        self.assertAlmostEqual(int(d["stakersWeeklyUSD_1e18"]) / E18, d["measuredUsdPerDay"] * 7 * 0.8, places=6)
        self.assertTrue(LEGACY_KEYS <= set(d))
        self.assertEqual(sorted(c["chainId"] for c in d["live"]["chains"]), [1, 4663, 8453])
        # the distributor's fundings are secondary information only
        self.assertEqual(d["fundedRealized"]["epoch"], E22)
        self.assertIn("NOT the headline", d["fundedRealized"]["basis"])
        # yield_history: epoch 22 Oct from the points at 22 Oct 02:31 and 29 Oct 02:31; keeper entries untouched
        yh = json.loads(w.repo.files[YH])
        self.assertEqual(yh["series"][:2], _keeper_history()["series"])
        self.assertEqual(len(yh["series"]), 2)     # 22 Oct is the keeper's: never rewritten
        # the claims state is persisted per chain
        st = json.loads(w.repo.files[LS])
        self.assertEqual(sorted(st["chains"]), ["1", "4663", "8453"])
        self.assertEqual(st["chains"]["4663"]["block"], w.sims[4663].block_of(RUN0 + 8 * DAY))

    def test_yield_history_gets_each_completed_epoch_measured(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        w.days(15)
        yh = json.loads(w.repo.files[YH])
        e29 = E22 + WEEK
        ours = [x for x in yh["series"] if x.get("method")]
        self.assertEqual([x["epoch"] for x in ours], [e29])          # 29 Oct (22 Oct is the keeper's entry)
        self.assertAlmostEqual(ours[0]["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5)
        self.assertEqual(ours[0]["method"], "measured")
        self.assertEqual(ours[0]["tvlUSD_1e18"], str(2_640_000 * E18))

    def test_yield_history_skipped_without_points_near_the_boundaries(self):
        # runs at 14:31 UTC: no point within 6 h of Thursday 00:00 -> no entry, the headline is still measured
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        for d in range(15):
            doc = w.run(RUN0 + 12 * 3600 + d * DAY)
        self.assertEqual(doc["apySource"], "measured-7d")
        self.assertEqual(json.loads(w.repo.files[YH])["series"], _keeper_history()["series"])

    def test_incomplete_read_keeps_the_headline_and_the_scan_resumes(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        rh = w.sims[4663]
        docs = w.days(9)
        block8 = json.loads(w.repo.files[LS])["chains"]["4663"]["block"]
        rh.logs_down = True                                         # day 9: Robinhood refuses eth_getLogs
        d9 = w.run(RUN0 + 9 * DAY)
        self.assertEqual((d9["apySource"], d9["apyPct"]), ("kept", docs[8]["apyPct"]))
        self.assertIn("claims not scanned on 4663", d9["staleReason"])
        self.assertTrue(d9["stale"])
        self.assertEqual(json.loads(w.repo.files[LS])["chains"]["4663"]["block"], block8)   # not advanced
        self.assertEqual(d9["live"]["history"][-1]["chains"], [1, 8453])                # Robinhood left out
        self.assertFalse(d9["live"]["history"][-1]["complete"])
        rh.logs_down = False
        rh.log_calls.clear()
        d10 = w.run(RUN0 + 10 * DAY)
        self.assertEqual(rh.log_calls, [block8 + 1])               # resumed from the persisted block
        self.assertEqual(d10["apySource"], "measured-7d")
        self.assertAlmostEqual(d10["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5)
        # 7 days after the incomplete point: the window ends at a complete neighbour 6-8 days old (review 8 M-1),
        # never at the incomplete point, and never the since-allocation average after week 1
        for d in range(11, 17):
            doc = w.run(RUN0 + d * DAY)
        self.assertIn(doc["live"]["trailing"]["7d"]["snapshotAsOf"], (RUN0 + 8 * DAY, RUN0 + 10 * DAY))
        self.assertTrue(doc["live"]["trailing"]["7d"]["complete"])
        self.assertEqual(doc["apySource"], "measured-7d")
        self.assertAlmostEqual(doc["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5)

    def test_restart_with_no_state_rescans_from_the_allocation(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        w.days(5)
        del w.repo.files[LS]
        for s in w.sims.values():
            s.log_calls.clear()
        doc = w.run(RUN0 + 5 * DAY)
        for cid, s in w.sims.items():
            self.assertEqual(s.log_calls, [s.block_of(T0)], cid)    # whole history once, from the allocation
        self.assertAlmostEqual(doc["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-6)
        self.assertEqual(json.loads(w.repo.files[LS])["chains"]["8453"]["block"], w.sims[8453].block_of(RUN0 + 5 * DAY))

    def test_unreachable_chain_keeps_the_headline(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        docs = w.days(3)
        doc = w.run(RUN0 + 3 * DAY, unreachable=(4663,))
        self.assertEqual((doc["apySource"], doc["apyPct"]), ("kept", docs[2]["apyPct"]))
        self.assertIn("chains not read [4663]", doc["staleReason"])
        self.assertEqual(doc["live"]["unmeasuredChains"], [4663])

    def test_robinhood_priced_through_the_mapping_table(self):
        # DefiLlama has no robinhood: prices -> the mapping table's keys (Ethereum WETH, coingecko global-dollar)
        got = {pe.ROBINHOOD_PRICE_MAP[RH_WETH]: 4000.0, pe.ROBINHOOD_PRICE_MAP[RH_USDG]: 1.0}
        rh = price_fetcher.MappedPriceFetcher(FakePF({}), pe.ROBINHOOD_PRICE_MAP)
        w = World(harvests=daily_harvests(), fundings=daily_fundings(), chain_prices={1: FakePF(PRICES[1]), 4663: rh},
                  llama=got)
        docs = w.days(2)
        self.assertEqual(docs[1]["apySource"], "measured-since-allocation")
        self.assertAlmostEqual(docs[1]["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-6)
        rh_tokens = {t["token"]: t for g in docs[1]["live"]["gauges"] if g["chainId"] == 4663 for t in g["tokens"]}
        self.assertAlmostEqual(rh_tokens[RH_USDG]["usd"], 232 * (RUN0 + DAY - T0) / 1e6, places=6)
        # USDG not resolvable through the mapping either: unpriced, the read is incomplete, the headline kept
        del got[pe.ROBINHOOD_PRICE_MAP[RH_USDG]]
        doc = w.run(RUN0 + 2 * DAY)
        self.assertEqual((doc["apySource"], doc["apyPct"]), ("kept", docs[1]["apyPct"]))
        self.assertEqual(doc["live"]["unpricedTokens"], [f"4663:{RH_USDG}"])
        self.assertIn("unpriced", doc["staleReason"])

    def test_untrusted_dex_price_is_left_out_of_the_measured_rate(self):
        # ported from review 2's RD_*: the new AERO has no aggregator price; its DEX price counts from a pool
        # >= DEX_TRUSTED_DEPTH_USD deep on its quote side, and is left out (listed, not "unpriced") otherwise
        for depth, env, counted in ((6_000_000.0, None, True), (30_000.0, None, False),
                                    (6_000_000.0, {"DEX_TRUSTED_DEPTH_USD": "10000000"}, False)):
            w = World(harvests=daily_harvests(), fundings=daily_fundings(), base_pf=FakePF(PRICES[8453], dex={AERO: depth}))
            for d in range(3):
                doc = w.run(RUN0 + d * DAY, env=env)
            leave = () if counted else ((8453, AERO),)
            want = usd_per_day(leave_out=leave) * 365 * 0.8 / STAKED_USD * 100
            self.assertEqual(doc["apySource"], "measured-since-allocation", depth)
            self.assertAlmostEqual(doc["apyPct"], want, delta=want * 1e-6)
            self.assertEqual(doc["live"]["excludedTokens"], [] if counted else [f"8453:{AERO}"])
            self.assertEqual(doc["live"]["unpricedTokens"], [])

    def test_untrusted_token_from_a_deep_single_lp_pool_is_left_out(self):
        # ported from review 3's R3_3: depth alone doesn't make a price trusted (token not in TRUSTED_DEX_TOKENS)
        w = World(harvests=daily_harvests(), fundings=daily_fundings(),
                  base_pf=FakePF(dict(PRICES[8453], **{USDC: 1.0}), dex={USDC: 1_200_000.0}))
        for d in range(3):
            doc = w.run(RUN0 + d * DAY)
        want = usd_per_day(leave_out=((8453, USDC),)) * 365 * 0.8 / STAKED_USD * 100
        self.assertAlmostEqual(doc["apyPct"], want, delta=want * 1e-6)
        self.assertEqual(doc["live"]["excludedTokens"], [f"8453:{USDC}"])

    def test_sanity_failure_keeps_the_headline(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings(),
                  base_pf=FakePF(dict(PRICES[8453], **{IAERO: 0.0001})))         # tiny denominator -> > 500%
        docs = w.days(3)
        self.assertEqual(docs[2]["apySource"], "kept")
        self.assertIn("sanity guard", docs[2]["staleReason"])
        self.assertEqual(docs[2]["apyPct"], previous_headline()["apyPct"])

    def test_aero_unpriced_keeps_the_headline(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings(), base_pf=FakePF({USDC: 1.0, WETH: 4000.0}))
        docs = w.days(3)
        self.assertEqual(docs[2]["apySource"], "kept")
        self.assertEqual(docs[2]["apyPct"], previous_headline()["apyPct"])

    def test_no_previous_headline_publishes_nothing(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings(), prev=False)
        self.assertIsNone(w.run(RUN0))                                   # under a day, nothing to keep
        self.assertNotIn(EST, w.updater.writes)
        self.assertIn(LS, w.updater.writes)                              # the claims state still advances

    def test_unreadable_previous_file_publishes_nothing(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        w.days(2)
        w.updater.writes.clear()
        w.repo.fail[EST] = Exception('503 {"message": "Service Unavailable"}')
        w.run(RUN0 + 2 * DAY)
        self.assertEqual(w.updater.writes, [])

    def test_live_failure_keeps_headline_and_previous_block(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        docs = w.days(3)
        doc = w.run(RUN0 + 3 * DAY, live_error=RuntimeError("429 Too Many Requests"))
        self.assertEqual((doc["apySource"], doc["apyPct"]), ("kept", docs[2]["apyPct"]))
        self.assertTrue(doc["live"]["stale"])
        self.assertEqual(doc["live"]["history"], docs[2]["live"]["history"])

    def test_each_file_can_be_disabled(self):
        w = World(harvests=daily_harvests(), fundings=daily_fundings())
        w.days(8, hook=None)
        w.updater.writes.clear()
        w.run(RUN0 + 14 * DAY, env={"ESTIMATED_REWARDS_ENABLED": "false"})
        self.assertNotIn(EST, w.updater.writes)
        self.assertIn(YH, w.updater.writes)
        w2 = World(harvests=daily_harvests(), fundings=daily_fundings())
        for d in range(15):
            w2.run(RUN0 + d * DAY, env={"YIELD_HISTORY_ENABLED": "false"})
        self.assertNotIn(YH, w2.updater.writes)
        self.assertIn(EST, w2.updater.writes)


class PayoutTimingTest(unittest.TestCase):
    """The headline is the stake's measured earning rate: when and how the harvester claims, and when and how much
    the distributor is funded (a partial payout, a catch-up lump, a test payout, a 9-day harvester outage), change
    nothing: the rewards keep accruing on chain, and claimed + unclaimed is what is measured."""

    DAYS = 22

    def series(self, harvests, fundings):
        w = World(harvests=harvests, fundings=fundings)
        docs = w.days(self.DAYS)
        hist = [x for x in json.loads(w.repo.files[YH])["series"] if x.get("method")]
        return docs, hist

    def test_headline_is_independent_of_payout_timing(self):
        day_usdc = round(usd_per_day() * 0.8 * 10 ** 6)
        scenarios = {
            "steady": (daily_harvests(), daily_fundings()),
            "partial payout": (daily_harvests(), daily_fundings(scale={3: 0.5, 4: 1.5})),
            "catch-up lump": (daily_harvests(), daily_fundings(scale={2: 0, 3: 0, 4: 0, 5: 4.0})),
            "test payout": (daily_harvests(), [(T0 - 3600, 1_000_000)] + daily_fundings()),
            "9-day harvester outage": (daily_harvests(skip=range(3, 12)),
                                       [f for f in daily_fundings() if not E22 + 3 * DAY <= f[0] < E22 + 12 * DAY]
                                       + [(E22 + 12 * DAY + 900, 9 * day_usdc)]),
        }
        out = {name: self.series(*s) for name, s in scenarios.items()}
        steady_docs, steady_hist = out["steady"]
        for name, (docs, hist) in out.items():
            for d, doc in enumerate(docs):
                if d == 0:
                    self.assertEqual(doc["apySource"], "kept", name)        # under a day after the allocation
                    continue
                self.assertIn(doc["apySource"], ("measured-since-allocation", "measured-7d"), (name, d))
                self.assertEqual(doc["apySource"], steady_docs[d]["apySource"], (name, d))
                self.assertAlmostEqual(doc["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5, msg=(name, d))
                self.assertAlmostEqual(doc["apyPct"], steady_docs[d]["apyPct"], delta=TRUE_APY * 1e-6, msg=(name, d))
            self.assertEqual([x["epoch"] for x in hist], [E22 + WEEK, E22 + 2 * WEEK], name)
            for x, y in zip(hist, steady_hist):
                self.assertAlmostEqual(x["apyPct"], y["apyPct"], delta=TRUE_APY * 1e-6, msg=name)
                self.assertAlmostEqual(x["apyPct"], TRUE_APY, delta=TRUE_APY * 1e-5, msg=name)
        # the fundings did differ: only the secondary fundedRealized figure follows them
        funded = {name: [docs[d]["fundedRealized"]["apyPct"] for d in (8, 15)] for name, (docs, _) in out.items()}
        self.assertNotEqual(funded["9-day harvester outage"], funded["steady"])
        self.assertNotEqual(funded["catch-up lump"][0], 0)


if __name__ == "__main__":
    unittest.main()
