# test_price_fetcher.py
# Unit tests for the on-chain DEX fallback in PriceFetcher (deepest Aero / Aerodrome pool, ~$10 quote).
# Uses a fake in-memory web3; no network. Run: python -m unittest discover -s tests
import json
import math
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from web3 import Web3  # noqa: E402

import price_fetcher  # noqa: E402
from price_fetcher import (  # noqa: E402
    PriceFetcher,
    AERODROME_FACTORY,
    AERO_VOLATILE_FACTORY,
    AERO_STABLE_FACTORY,
)

cs = Web3.to_checksum_address

USDC = cs("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
WETH = cs("0x4200000000000000000000000000000000000006")
AERO = cs("0x3f5bF3EdAc59d650D8fDf9657a71F2f904A3a4Ee")
OLD_AERO = cs("0x940181a94A35A4569E4529A3CDfB74e38FD98631")
LIQ = cs("0x7ee8964160126081cebC443a42482E95e393e6A8")
IAERO = cs("0x81034Fb34009115F215f5d5F564AAc9FfA46a1Dc")


class Reverted(Exception):
    pass


class FakeChain:
    """Minimal model of Aero (getPool(a,b)) and Aerodrome (getPool(a,b,bool)) factories + v2 pools."""

    def __init__(self):
        self.aero = {cs(AERO_VOLATILE_FACTORY): {}, cs(AERO_STABLE_FACTORY): {}}
        self.aerodrome = {cs(AERODROME_FACTORY): {}}
        self.pools = {}  # pool -> {token: reserve}
        self.cl = {}     # CL pool -> (token0, token1, sqrtPriceX96)
        self.decimals = {USDC: 6, WETH: 18, AERO: 18, OLD_AERO: 18, LIQ: 18, IAERO: 18}
        self._n = 0

    def _new_pool(self, ta, ra, tb, rb):
        self._n += 1
        pool = cs("0x" + format(0xB0000 + self._n, "040x"))
        self.pools[pool] = {cs(ta): ra, cs(tb): rb}
        return pool

    def add_aero_pool(self, factory, ta, ra, tb, rb):
        pool = self._new_pool(ta, ra, tb, rb)
        self.aero.setdefault(cs(factory), {})[frozenset((cs(ta), cs(tb)))] = pool
        return pool

    def add_aerodrome_pool(self, stable, ta, ra, tb, rb):
        pool = self._new_pool(ta, ra, tb, rb)
        self.aerodrome[cs(AERODROME_FACTORY)][(frozenset((cs(ta), cs(tb))), stable)] = pool
        return pool

    def call(self, address, name, args):
        zero = "0x" + "00" * 20
        if address in self.aero:
            # Aero factories only implement getPool(a,b); getPair / getPool(a,b,bool) revert
            if name != "getPool" or len(args) != 2:
                raise Reverted("execution reverted")
            return self.aero[address].get(frozenset((cs(args[0]), cs(args[1]))), zero)
        if address in self.aerodrome:
            # Aerodrome PoolFactory implements getPool(a,b,bool); getPair is not deployed
            if name != "getPool" or len(args) != 3:
                raise Reverted("execution reverted")
            return self.aerodrome[address].get((frozenset((cs(args[0]), cs(args[1]))), bool(args[2])), zero)
        if address in self.cl and name in ("token0", "token1", "slot0"):
            t0, t1, sp = self.cl[address]
            return {"token0": t0, "token1": t1, "slot0": [sp, 0, 0, 1, 1, True]}[name]
        if address in self.pools and name in ("token0", "token1", "getReserves"):
            t0, t1 = sorted(self.pools[address], key=str.lower)        # pools order their tokens by address
            return {"token0": t0, "token1": t1}.get(name) or [self.pools[address][t0], self.pools[address][t1], 0]
        if address in self.pools and name == "getAmountOut":
            amount_in, token_in = args
            reserves = self.pools[address]
            r_in = reserves[cs(token_in)]
            r_out = [r for t, r in reserves.items() if t != cs(token_in)][0]
            return amount_in * r_out // (r_in + amount_in)
        if name == "decimals" and address in self.decimals:
            return self.decimals[address]
        raise Reverted("execution reverted")


def fake_web3_cls(chain):
    class _Fn:
        def __init__(self, address, name, abi):
            self.address, self.name, self.abi = address, name, abi

        def __call__(self, *args):
            # like web3: the ABI must declare a function with this name and arity
            if not any(e.get("name") == self.name and len(e.get("inputs", [])) == len(args) for e in self.abi):
                raise ValueError(f"no ABI match for {self.name}{args}")
            return mock.Mock(call=lambda: chain.call(self.address, self.name, args))

    class _Functions:
        def __init__(self, address, abi):
            self._address, self._abi = address, abi

        def __getattr__(self, name):
            return _Fn(self._address, name, self._abi)

    class _Eth:
        def contract(self, address, abi=None):
            return mock.Mock(functions=_Functions(cs(address), abi or []))

    class FakeWeb3:
        HTTPProvider = staticmethod(lambda *a, **k: None)
        to_checksum_address = staticmethod(Web3.to_checksum_address)

        def __init__(self, provider=None):
            self.eth = _Eth()

    return FakeWeb3


class PriceFetcherDexTest(unittest.TestCase):
    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in ("AERO_VOLATILE_FACTORY", "AERO_STABLE_FACTORY", "COINGECKO_API_KEY"):
            os.environ.pop(k, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.chain = FakeChain()
        # WETH/USDC on both DEXes at $4000
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, WETH, 10_000 * 10**18, USDC, 40_000_000 * 10**6)
        self.chain.add_aerodrome_pool(False, WETH, 10_000 * 10**18, USDC, 40_000_000 * 10**6)

    def make_pf(self, **kw):
        kw.setdefault("aerodrome_factory", None)  # main.py passes None when AERODROME_FACTORY is unset
        # fresh cache file per fetcher, so cached entries never leak between fetchers
        cache_file = os.path.join(tempfile.mkdtemp(dir=self.tmp.name), "price_cache.json")
        with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(self.chain)):
            pf = PriceFetcher(
                cache_file=cache_file,
                rpc_url="http://fake-rpc",
                usdc=USDC,
                weth=WETH,
                **kw,
            )
        # aggregators have no price for the new AERO; force the DEX fallback
        pf._fetch_llama = lambda addrs: {}
        pf._fetch_coingecko = lambda addrs: {}
        return pf

    def price(self, pf, token):
        return pf.fetch_batch([token.lower()])[token.lower()]

    def test_new_aero_priced_from_aero_volatile_usdc_pool(self):
        # deep AERO/USDC volatile pool, as on mainnet: ~6.5M AERO / ~5.265M USDC -> ~$0.81
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, AERO, 6_500_000 * 10**18, USDC, 5_265_000 * 10**6)
        e = self.price(self.make_pf(), AERO)
        self.assertEqual(e["source"], "dex")
        self.assertAlmostEqual(e["priceUsd"], 0.81, places=4)
        self.assertEqual(e["dexDepthUsd"], 5_265_000.0)                 # quote-side depth of the pool used
        self.assertEqual(e["dexPool"], self.chain.aero[AERO_VOLATILE_FACTORY][frozenset((AERO, USDC))])

    def test_aero_weth_hop_and_stable_factory(self):
        # LIQ only paired with WETH, on the Aero stable factory -> LIQ->WETH x WETH->USDC
        self.chain.add_aero_pool(AERO_STABLE_FACTORY, LIQ, 2_000_000 * 10**18, WETH, 10 * 10**18)
        e = self.price(self.make_pf(), LIQ)
        self.assertEqual(e["source"], "dex")
        self.assertAlmostEqual(e["priceUsd"], 0.02, places=4)  # 1/200000 WETH * $4000

    def test_deepest_pool_wins_across_dexes(self):
        # a shallower Aero pool no longer beats a deeper Aerodrome pool (and vice versa)
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, LIQ, 1_000_000 * 10**18, USDC, 30_000 * 10**6)
        self.chain.add_aerodrome_pool(False, LIQ, 1_000_000 * 10**18, USDC, 50_000 * 10**6)
        e = self.price(self.make_pf(aerodrome_factory=AERODROME_FACTORY), LIQ)
        self.assertAlmostEqual(e["priceUsd"], 0.05, places=4)
        self.chain.add_aero_pool(AERO_STABLE_FACTORY, LIQ, 1_000_000 * 10**18, USDC, 90_000 * 10**6)
        self.assertAlmostEqual(self.price(self.make_pf(), LIQ)["priceUsd"], 0.09, places=4)

    def test_pool_below_min_depth_is_not_used(self):
        # $20k of USDC on the quote side < $25k: unpriced rather than priced from a thin pool
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, LIQ, 1_000_000 * 10**18, USDC, 20_000 * 10**6)
        self.assertEqual(self.price(self.make_pf(), LIQ)["source"], "none")
        self.assertAlmostEqual(self.price(self.make_pf(dex_min_quote_usd=10_000), LIQ)["priceUsd"], 0.02, places=4)

    def test_weth_route_wins_when_deeper_than_usdc(self):
        # thin LIQ/USDC pool at a skewed $1.00; deep LIQ/WETH pool ($400k of WETH) at $0.02
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, LIQ, 30_000 * 10**18, USDC, 30_000 * 10**6)
        self.chain.add_aerodrome_pool(False, LIQ, 20_000_000 * 10**18, WETH, 100 * 10**18)
        e = self.price(self.make_pf(), LIQ)
        self.assertAlmostEqual(e["priceUsd"], 0.02, places=4)
        self.assertAlmostEqual(e["dexDepthUsd"], 400_000.0, delta=10)     # 100 WETH at ~$4,000

    def test_high_price_token_quoted_with_small_notional(self):
        # a whole BTC swapped into a $128k pool would read ~$50k; a ~$10 swap reads the pool price
        BTC = cs("0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf")
        self.chain.decimals[BTC] = 8
        self.chain.add_aerodrome_pool(False, BTC, 157_511_593, USDC, 128_827_784_341)
        e = self.price(self.make_pf(), BTC)
        self.assertAlmostEqual(e["priceUsd"], 128_827.784341 / 1.57511593, delta=10)

    def test_zero_price_is_never_cached(self):
        pf = self.make_pf()
        self.assertEqual(self.price(pf, AERO)["source"], "none")
        self.assertNotIn(f"base:{AERO.lower()}", pf.mem)
        with open(pf.cache_file) as f:
            self.assertNotIn(f"base:{AERO.lower()}", json.load(f))
        # a stale cache file holding a 0.0 entry is ignored
        with open(pf.cache_file, "w") as f:
            json.dump({f"base:{AERO.lower()}": {"priceUsd": 0.0, "updatedAt": price_fetcher._now(), "source": "none"}}, f)
        pf2 = PriceFetcher(cache_file=pf.cache_file)
        self.assertEqual(pf2.mem, {})
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, AERO, 6_500_000 * 10**18, USDC, 5_265_000 * 10**6)
        self.assertEqual(self.price(pf, AERO)["source"], "dex")       # retried on the next call

    def test_default_cap_keeps_btc_prices(self):
        self.assertGreaterEqual(PriceFetcher(cache_file=os.path.join(self.tmp.name, "c.json")).max_price_usd, 1_000_000)

    def test_falls_back_to_aerodrome_for_legacy_tokens(self):
        # old AERO has no Aero pools; Aerodrome uses getPool(a,b,bool) (getPair would revert)
        self.chain.add_aerodrome_pool(False, OLD_AERO, 1_000_000 * 10**18, USDC, 810_000 * 10**6)
        e = self.price(self.make_pf(), OLD_AERO)
        self.assertEqual(e["source"], "dex")
        self.assertAlmostEqual(e["priceUsd"], 0.81, places=4)

    def test_aerodrome_weth_hop(self):
        self.chain.add_aerodrome_pool(True, OLD_AERO, 40_000 * 10**18, WETH, 10 * 10**18)   # $40k of WETH
        e = self.price(self.make_pf(aerodrome_factory=AERODROME_FACTORY), OLD_AERO)
        self.assertGreater(e["priceUsd"], 0.99)
        self.assertLess(e["priceUsd"], 1.01)

    def test_unquotable_token_is_zero(self):
        e = self.price(self.make_pf(), AERO)
        self.assertEqual(e, {"priceUsd": 0.0, "updatedAt": e["updatedAt"], "source": "none"})

    def test_aero_factories_configurable_by_env(self):
        other = cs("0x00000000000000000000000000000000000a3e01")
        self.chain.aero[other] = {}
        self.chain.add_aero_pool(other, AERO, 1_000_000 * 10**18, USDC, 700_000 * 10**6)
        self.assertEqual(self.price(self.make_pf(), AERO)["source"], "none")  # default factory: no pool
        os.environ["AERO_VOLATILE_FACTORY"] = other
        e = self.price(self.make_pf(), AERO)
        self.assertAlmostEqual(e["priceUsd"], 0.70, places=4)

    def test_no_rpc_disables_dex(self):
        pf = PriceFetcher(cache_file=os.path.join(self.tmp.name, "c.json"))
        self.assertIsNone(pf._dex_price_one(AERO))



RH_WETH = "0x0bd7d308f8e1639fab988df18a8011f41eacad73"
RH_USDG = "0x5fc5360d0400a0fd4f2af552add042d716f1d168"


class _Base:
    def __init__(self, prices):
        self.prices = prices

    def fetch_batch(self, addrs):
        return {a: {"priceUsd": self.prices.get(a, 0.0), "updatedAt": 0, "source": "llama" if a in self.prices else "none"}
                for a in addrs}


class RobinhoodPricingTest(unittest.TestCase):
    """Robinhood (4663): DefiLlama robinhood:<address> first; else the explicit mapping table; never a guess."""

    def test_mapping_table(self):
        import position_earnings as pe
        self.assertEqual(pe.ROBINHOOD_PRICE_MAP, {
            RH_WETH: "ethereum:0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",       # Robinhood WETH -> Ethereum WETH
            RH_USDG: "coingecko:global-dollar"})                                  # USDG -> its coingecko id

    def test_native_price_first_then_mapping_then_unpriced(self):
        mp = price_fetcher.MappedPriceFetcher(_Base({RH_WETH: 2400.0}), {RH_WETH: "ethereum:0xw", RH_USDG: "coingecko:g"})
        with mock.patch.object(price_fetcher, "llama_prices", return_value={"coingecko:g": 0.9999}) as lp:
            out = mp.fetch_batch([RH_WETH, RH_USDG, "0xother"])
        lp.assert_called_once_with(["coingecko:g"])                              # only what the chain didn't price
        self.assertEqual((out[RH_WETH]["priceUsd"], out[RH_WETH]["source"]), (2400.0, "llama"))
        self.assertEqual((out[RH_USDG]["priceUsd"], out[RH_USDG]["source"]), (0.9999, "mapped:coingecko:g"))
        self.assertEqual((out["0xother"]["priceUsd"], out["0xother"]["source"]), (0.0, "none"))    # not mapped
        with mock.patch.object(price_fetcher, "llama_prices", return_value={}):
            out = mp.fetch_batch([RH_USDG])
        self.assertEqual(out[RH_USDG]["priceUsd"], 0.0)                         # mapped key unpriced too

    def test_native_robinhood_key_is_tried_first(self):
        pf = price_fetcher.PriceFetcher(chain_slug="robinhood", cache_file=os.path.join(tempfile.mkdtemp(), "c.json"))
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"coins": {f"robinhood:{RH_WETH}": {"price": 2384.5}}}
        with mock.patch.object(price_fetcher.requests, "get", return_value=resp) as get:
            got = pf._fetch_llama([RH_WETH])
        self.assertIn(f"robinhood:{RH_WETH}", get.call_args.args[0])
        self.assertEqual(got[RH_WETH]["priceUsd"], 2384.5)

    def test_llama_prices_keeps_only_positive_finite(self):
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"coins": {"a:1": {"price": 2.0}, "a:2": {"price": 0}, "a:3": {"price": float("nan")},
                                            "a:4": {}}}
        with mock.patch.object(price_fetcher.requests, "get", return_value=resp):
            self.assertEqual(price_fetcher.llama_prices(["a:1", "a:2", "a:3", "a:4"]), {"a:1": 2.0})
        with mock.patch.object(price_fetcher.requests, "get", return_value=mock.Mock(status_code=502, text="bad")), \
             mock.patch.object(price_fetcher.time, "sleep"):                  # 502s are retried (bounded)
            self.assertEqual(price_fetcher.llama_prices(["a:1"]), {})
        with mock.patch.object(price_fetcher.requests, "get", side_effect=OSError("down")), \
             mock.patch.object(price_fetcher.time, "sleep"):
            self.assertEqual(price_fetcher.llama_prices(["a:1"]), {})
        self.assertEqual(price_fetcher.llama_prices([]), {})



class IaeroRouteTest(unittest.TestCase):
    """Operational blocker I-1 (review 8): DefiLlama's iAERO price went stale when the Aerodrome pools were drained and
    no USDC/WETH route exists, so iAERO = AERO price x AERO per iAERO from the Aero AERO/iAERO CL pool, cross-checked
    against the v2 pool; core-token aggregator prices older than 2 h count as missing."""
    NOW = 1_792_703_700

    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in ("COINGECKO_API_KEY", "DEX_TRUSTED_DEPTH_USD", "TRUSTED_DEX_TOKENS"):
            os.environ.pop(k, None)
        self.chain = FakeChain()
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, WETH, 10_000 * 10**18, USDC, 40_000_000 * 10**6)
        self.set_pools(0.816, 46_441, 56_913)

    def set_pools(self, cl_aero_per_iaero, v2_aero, v2_iaero):
        """CL slot0 at `cl_aero_per_iaero` AERO per iAERO (token0 AERO, token1 iAERO); v2 reserves."""
        sp = int(math.sqrt(1 / cl_aero_per_iaero) * 2 ** 96)
        self.chain.cl[cs(price_fetcher.IAERO_CL_POOL)] = (AERO, IAERO, sp)
        self.chain.pools[cs(price_fetcher.IAERO_V2_POOL)] = {AERO: v2_aero * 10**18, IAERO: v2_iaero * 10**18}

    def make_pf(self, llama=None, cg=None):
        with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(self.chain)):
            pf = PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"), rpc_url="http://fake", usdc=USDC,
                              weth=WETH, aerodrome_factory=None)
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"coins": {f"base:{a.lower()}": v for a, v in (llama or {}).items()}}
        self.llama_resp = resp
        pf._fetch_coingecko = lambda addrs: {}
        return pf

    def fetch(self, pf, tokens):
        with mock.patch.object(price_fetcher.requests, "get", return_value=self.llama_resp), \
             mock.patch.object(price_fetcher, "_now", return_value=self.NOW):
            return pf.fetch_batch([t.lower() for t in tokens])

    def test_stale_llama_iaero_is_replaced_by_the_route(self):
        pf = self.make_pf({AERO: {"price": 0.8, "timestamp": self.NOW - 60},
                           IAERO: {"price": 0.6656, "timestamp": self.NOW - 9 * 3600},     # stale since 12:21 UTC
                           LIQ: {"price": 0.02, "timestamp": self.NOW - 9 * 3600}})       # not a core token: kept
        out = self.fetch(pf, [AERO, IAERO, LIQ])
        ia = out[IAERO.lower()]
        self.assertEqual(ia["source"], "route")
        self.assertAlmostEqual(ia["priceUsd"], 0.8 * 0.816, places=9)
        self.assertAlmostEqual(ia["route"]["aeroPerIaero"], 0.816, places=9)
        self.assertAlmostEqual(ia["route"]["aeroPerIaeroV2"], 0.816, places=3)               # a 1-iAERO v2 swap
        self.assertEqual((ia["route"]["aeroSource"], ia["route"]["clPool"]),
                         ("llama", price_fetcher.IAERO_CL_POOL.lower()))
        self.assertEqual((out[AERO.lower()]["source"], out[LIQ.lower()]["priceUsd"]), ("llama", 0.02))

    def test_fresh_llama_iaero_is_used_as_is(self):
        pf = self.make_pf({AERO: {"price": 0.8, "timestamp": self.NOW}, IAERO: {"price": 0.66, "timestamp": self.NOW - 600}})
        self.assertEqual(self.fetch(pf, [AERO, IAERO])[IAERO.lower()], {"priceUsd": 0.66, "updatedAt": self.NOW,
                                                                           "source": "llama"})

    def test_pools_disagreeing_by_more_than_3pct_leave_iaero_unpriced(self):
        self.set_pools(0.816, 46_441, 50_000)                                  # v2 ~0.926: 13% apart
        pf = self.make_pf({AERO: {"price": 0.8, "timestamp": self.NOW}})
        ia = self.fetch(pf, [AERO, IAERO])[IAERO.lower()]
        self.assertEqual((ia["priceUsd"], ia["source"]), (0.0, "none"))
        self.set_pools(0.816, 46_441, 56_000)                                  # v2 ~0.828: 1.5% apart -> ok
        ia = self.fetch(self.make_pf({AERO: {"price": 0.8, "timestamp": self.NOW}}), [AERO, IAERO])[IAERO.lower()]
        self.assertEqual(ia["source"], "route")

    def test_the_aero_price_must_be_trusted(self):
        # AERO stale on DefiLlama too -> DEX fallback; from a $30k pool it is not trusted -> iAERO unpriced, and the
        # generic DEX fallback is never used for iAERO (even with an iAERO/USDC pool)
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, AERO, 37_000 * 10**18, USDC, 30_000 * 10**6)
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, IAERO, 1_000_000 * 10**18, USDC, 900_000 * 10**6)
        pf = self.make_pf({AERO: {"price": 0.8, "timestamp": self.NOW - 3 * 3600}})
        out = self.fetch(pf, [AERO, IAERO])
        self.assertEqual(out[AERO.lower()]["source"], "dex")
        self.assertEqual((out[IAERO.lower()]["priceUsd"], out[IAERO.lower()]["source"]), (0.0, "none"))
        # from a deep ($5.3M) pool it is trusted -> the route prices iAERO
        chain = self.chain
        self.chain = FakeChain()
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, WETH, 10_000 * 10**18, USDC, 40_000_000 * 10**6)
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, AERO, 6_500_000 * 10**18, USDC, 5_265_000 * 10**6)
        self.set_pools(0.816, 46_441, 56_913)
        out = self.fetch(self.make_pf({}), [AERO, IAERO])
        self.assertEqual(out[IAERO.lower()]["source"], "route")
        self.assertAlmostEqual(out[IAERO.lower()]["priceUsd"], out[AERO.lower()]["priceUsd"] * 0.816, places=9)
        self.assertEqual(out[IAERO.lower()]["route"]["aeroSource"], "dex")
        del chain

    def test_stale_or_undated_coingecko_core_price_is_dropped(self):
        pf = self.make_pf({})
        del pf._fetch_coingecko
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {IAERO.lower(): {"usd": 0.6656, "last_updated_at": self.NOW - 5 * 3600},
                                  LIQ.lower(): {"usd": 0.02}}
        with mock.patch.object(price_fetcher.requests, "get", return_value=resp) as get, \
             mock.patch.object(price_fetcher, "_now", return_value=self.NOW):
            got = pf._fetch_coingecko([IAERO.lower(), LIQ.lower()])
        self.assertEqual(sorted(got), [LIQ.lower()])
        self.assertEqual(get.call_args.kwargs["params"]["include_last_updated_at"], "true")

    def test_iaero_price_source_is_recorded(self):
        import realized_yield as ry
        p = ry.compute_realized(1, [], 10**24, 10**24, iaero_price=0.65, aero_price=0.8, iaero_price_source="route",
                                iaero_price_route={"aeroPerIaero": 0.816})
        self.assertEqual((p["iaeroPriceSource"], p["iaeroPriceRoute"]), ("route", {"aeroPerIaero": 0.816}))
        p = ry.compute_realized(1, [], 10**24, 10**24, iaero_price=0.0, aero_price=0.8, iaero_price_source="none")
        self.assertEqual(p["iaeroPriceSource"], "fallback:aero")
        self.assertNotIn("iaeroPriceRoute", p)
        self.assertIn("iAERO is unpriced", ry.sanity_problems(p))


LLAMA_PREFIX = price_fetcher.LLAMA_URL.format("")


def _base_keys(n):
    return [f"base:0x{0xA0000 + i:040x}" for i in range(n)]


class FakeHttp:
    """requests.get stand-in. DefiLlama URLs are answered from `llama` ({key: coin}) with the status that
    llama_status(keys, try number for that URL) returns (an Exception is raised); CoinGecko from `cg` ({addr: entry})."""

    def __init__(self, llama=None, cg=None, llama_status=None):
        self.llama, self.cg = llama or {}, cg or {}
        self.llama_status = llama_status or (lambda keys, n: 200)
        self.llama_urls, self.cg_calls = [], []

    def __call__(self, url, params=None, headers=None, timeout=None):
        if url.startswith(LLAMA_PREFIX):
            keys = url[len(LLAMA_PREFIX):].split(",")
            self.llama_urls.append(url)
            st = self.llama_status(keys, self.llama_urls.count(url))
            if isinstance(st, Exception):
                raise st
            r = mock.Mock(status_code=st, text='{"error":"URL too long"}' if st == 414 else "err")
            r.json.return_value = {"coins": {k: self.llama[k] for k in keys if k in self.llama}}
            return r
        self.cg_calls.append(params)
        r = mock.Mock(status_code=200, text="")
        r.json.return_value = {a: self.cg[a] for a in params["contract_addresses"].split(",") if a in self.cg}
        return r


class LlamaBatchingTest(unittest.TestCase):
    """2 Nov 2026 run: 437 registry tokens in one DefiLlama URL -> HTTP 414 (20,991 chars, max 9,000 on the free tier)
    -> Llama filled 0 / 437 and 191 tokens ended unpriced. Requests are now split by URL length; a failed batch loses
    only its own tokens; retries are bounded."""

    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in ("COINGECKO_API_KEY", "LLAMA_MAX_URL_CHARS"):
            os.environ.pop(k, None)
        sleep = mock.patch.object(price_fetcher.time, "sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def pf(self):
        return PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"))

    def test_437_registry_tokens_fit_in_batches_under_the_limit(self):
        keys = _base_keys(437)
        self.assertGreater(len(price_fetcher.LLAMA_URL.format(",".join(keys))), 20_000)    # the one URL of 2 Nov
        batches = price_fetcher.llama_batches(keys)
        self.assertEqual([k for b in batches for k in b], keys)                            # all, once, in order
        self.assertEqual(len(batches), 3)                                                  # 165 + 165 + 107
        for b in batches:
            self.assertLessEqual(len(price_fetcher.LLAMA_URL.format(",".join(b))), price_fetcher.LLAMA_MAX_URL_CHARS)
        self.assertLess(price_fetcher.LLAMA_MAX_URL_CHARS, 9_000)

    def test_url_length_boundary(self):
        keys = _base_keys(3)
        n = len(price_fetcher.LLAMA_URL.format(",".join(keys)))
        self.assertEqual(price_fetcher.llama_batches(keys, max_url_chars=n), [keys])          # exactly at the limit
        self.assertEqual(price_fetcher.llama_batches(keys, max_url_chars=n - 1), [keys[:2], keys[2:]])
        # sized by length, not count: the same limit holds three short keys or one long one
        short, long_ = ["a:1", "a:2", "a:3"], ["coingecko:" + "x" * 30, "coingecko:" + "y" * 30]
        limit = len(LLAMA_PREFIX) + len("a:1,a:2,a:3")
        self.assertEqual(len(price_fetcher.llama_batches(short, max_url_chars=limit)), 1)
        self.assertEqual(len(price_fetcher.llama_batches(long_, max_url_chars=limit)), 2)     # each alone, oversized
        self.assertEqual(price_fetcher.llama_batches([]), [])

    def test_env_limit_and_bad_values(self):
        keys = _base_keys(100)
        os.environ["LLAMA_MAX_URL_CHARS"] = "2000"
        small = price_fetcher.llama_batches(keys)
        self.assertGreater(len(small), 2)
        self.assertTrue(all(len(price_fetcher.LLAMA_URL.format(",".join(b))) <= 2000 for b in small))
        for bad in ("abc", "0", "-5"):
            os.environ["LLAMA_MAX_URL_CHARS"] = bad
            self.assertEqual(len(price_fetcher.llama_batches(keys)), 1)                     # default 8,000

    def test_every_batch_is_requested_and_merged(self):
        keys = _base_keys(437)
        http = FakeHttp(llama={k: {"price": 1.0 + i, "timestamp": 0} for i, k in enumerate(keys)})
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            got = self.pf()._fetch_llama([k.split(":")[1] for k in keys])
        self.assertEqual(len(got), 437)
        self.assertEqual(len(http.llama_urls), 3)
        self.assertTrue(all(len(u) <= price_fetcher.LLAMA_MAX_URL_CHARS for u in http.llama_urls))

    def test_one_failed_batch_does_not_unprice_the_others(self):
        keys = _base_keys(437)
        bad = price_fetcher.llama_batches(keys)[1]
        addrs = [k.split(":")[1] for k in keys]
        for failure in (414, requests_error()):
            http = FakeHttp(llama={k: {"price": 2.0, "timestamp": 0} for k in keys},
                            cg={a: {"usd": 3.0} for a in addrs},
                            llama_status=lambda ks, n, f=failure: f if ks == bad else 200)
            with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
                out = self.pf().fetch_batch(addrs)
            src = {a: out[a]["source"] for a in addrs}
            self.assertEqual(sum(s == "llama" for s in src.values()), 437 - len(bad))
            self.assertEqual({src[k.split(":")[1]] for k in bad}, {"coingecko"})          # only this batch falls back
            self.assertTrue(all(out[a]["priceUsd"] > 0 for a in addrs))
            cg_asked = [a for p in http.cg_calls for a in p["contract_addresses"].split(",")]
            self.assertEqual(sorted(cg_asked), sorted(k.split(":")[1] for k in bad))

    def test_retries_are_bounded(self):
        keys = _base_keys(2)
        price = {k: {"price": 1.5, "timestamp": 0} for k in keys}
        tries = price_fetcher.LLAMA_RETRIES + 1
        # 503 every time: LLAMA_RETRIES + 1 requests, then the batch is given up
        http = FakeHttp(llama=price, llama_status=lambda ks, n: 503)
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            self.assertEqual(price_fetcher.llama_prices(keys), {})
        self.assertEqual(len(http.llama_urls), tries)
        self.assertEqual([c.args[0] for c in self.sleep.call_args_list],
                         [price_fetcher.LLAMA_RETRY_BACKOFF_SEC * i for i in range(1, tries)])
        # an exception every time: same bound
        http = FakeHttp(llama=price, llama_status=lambda ks, n: requests_error())
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            self.assertEqual(self.pf()._fetch_llama([k.split(":")[1] for k in keys]), {})
        self.assertEqual(len(http.llama_urls), tries)
        # 429, then 200: priced on the second try
        http = FakeHttp(llama=price, llama_status=lambda ks, n: 429 if n == 1 else 200)
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            self.assertEqual(price_fetcher.llama_prices(keys), {k: 1.5 for k in keys})
        self.assertEqual(len(http.llama_urls), 2)
        # 414 (or any other 4xx) is final: one request
        http = FakeHttp(llama=price, llama_status=lambda ks, n: 414)
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            self.assertEqual(price_fetcher.llama_prices(keys), {})
        self.assertEqual(len(http.llama_urls), 1)

    def test_llama_prices_batches_mixed_keys(self):
        keys = _base_keys(300) + [f"coingecko:token-{i}" for i in range(50)] + ["ethereum:0x" + "c0" * 20]
        http = FakeHttp(llama={k: {"price": 4.0} for k in keys})
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http):
            got = price_fetcher.llama_prices(keys)
        self.assertEqual(got, {k: 4.0 for k in keys})
        self.assertGreater(len(http.llama_urls), 1)
        self.assertTrue(all(len(u) <= price_fetcher.LLAMA_MAX_URL_CHARS for u in http.llama_urls))

    def test_done_log_counts_only_priced_tokens(self):
        keys = _base_keys(2)
        http = FakeHttp(llama={keys[0]: {"price": 1.0}})
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http), \
             self.assertLogs("price_fetcher", level="INFO") as logs:
            self.pf().fetch_batch([k.split(":")[1] for k in keys])
        self.assertTrue(any("Total priced: 1 / 2" in m for m in logs.output), logs.output)


def requests_error():
    return price_fetcher.requests.ConnectionError("connection reset")


class IaeroPricingPathTest(unittest.TestCase):
    """iAERO (a core token; the realized APY's denominator) on 2 Nov 2026: DefiLlama has no iAERO price, CoinGecko's
    is ~56 h old (last_updated_at 1793402249). Neither may be used; iAERO comes from the AERO/iAERO pools route.
    A stale price is never used, even when nothing else prices iAERO."""
    NOW = 1_793_603_689
    AERO_PX = 0.6176172214432898

    def setUp(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for k in ("COINGECKO_API_KEY", "DEX_TRUSTED_DEPTH_USD", "TRUSTED_DEX_TOKENS", "LLAMA_MAX_URL_CHARS"):
            os.environ.pop(k, None)
        self.chain = FakeChain()
        self.chain.add_aero_pool(AERO_VOLATILE_FACTORY, WETH, 10_000 * 10**18, USDC, 40_000_000 * 10**6)
        # the route pools as read on 2 Nov (block 53407143): CL ~0.819 AERO per iAERO; v2 46,368 AERO / 57,003 iAERO
        self.set_pools(0.8189, 46_368, 57_003)

    def set_pools(self, cl_aero_per_iaero, v2_aero, v2_iaero):
        sp = int(math.sqrt(1 / cl_aero_per_iaero) * 2 ** 96)
        self.chain.cl[cs(price_fetcher.IAERO_CL_POOL)] = (AERO, IAERO, sp)
        self.chain.pools[cs(price_fetcher.IAERO_V2_POOL)] = {AERO: v2_aero * 10**18, IAERO: v2_iaero * 10**18}

    def fetch(self, llama, cg, tokens=(AERO, IAERO, LIQ)):
        with mock.patch.object(price_fetcher, "Web3", fake_web3_cls(self.chain)):
            pf = PriceFetcher(cache_file=os.path.join(tempfile.mkdtemp(), "c.json"), rpc_url="http://fake", usdc=USDC,
                              weth=WETH, aerodrome_factory=None)
        http = FakeHttp(llama={f"base:{a.lower()}": v for a, v in llama.items()},
                        cg={a.lower(): v for a, v in cg.items()})
        with mock.patch.object(price_fetcher.requests, "get", side_effect=http), \
             mock.patch.object(price_fetcher, "_now", return_value=self.NOW), \
             mock.patch.object(price_fetcher.time, "sleep"), \
             self.assertLogs("price_fetcher", level="INFO") as logs:
            out = pf.fetch_batch([t.lower() for t in tokens])
        return out, pf, "\n".join(logs.output)

    def llama_aero(self):
        return {AERO: {"price": self.AERO_PX, "timestamp": self.NOW - 60}}

    def test_stale_coingecko_and_missing_llama_price_iaero_from_the_route(self):
        # the 2 Nov state: DefiLlama: AERO only; CoinGecko: iAERO 56 h old
        out, pf, logs = self.fetch(self.llama_aero(), {IAERO: {"usd": 0.499549, "last_updated_at": 1793402249},
                                                       LIQ: {"usd": 0.02}})
        ia = out[IAERO.lower()]
        self.assertEqual(ia["source"], "route")
        self.assertAlmostEqual(ia["priceUsd"], self.AERO_PX * 0.8189, places=6)
        self.assertEqual(ia["route"]["aeroSource"], "llama")
        self.assertEqual(pf.mem[f"base:{IAERO.lower()}"]["source"], "route")
        self.assertIn(f"CoinGecko price of core token {IAERO.lower()} is 56.0 h old (> 2 h); not used "
                      f"(the AERO/iAERO pools route is tried next)", logs)
        self.assertNotIn("treated as unpriced", logs)
        self.assertEqual((out[LIQ.lower()]["source"], out[LIQ.lower()]["priceUsd"]), ("coingecko", 0.02))  # undated, kept

    def test_fresh_aggregator_iaero_is_used(self):
        out, _, _ = self.fetch(self.llama_aero(), {IAERO: {"usd": 0.5051, "last_updated_at": self.NOW - 600}})
        self.assertEqual((out[IAERO.lower()]["source"], out[IAERO.lower()]["priceUsd"]), ("coingecko", 0.5051))
        llama = {**self.llama_aero(), IAERO: {"price": 0.5049, "timestamp": self.NOW - 3600}}
        out, _, _ = self.fetch(llama, {})
        self.assertEqual((out[IAERO.lower()]["source"], out[IAERO.lower()]["priceUsd"]), ("llama", 0.5049))

    def test_undated_llama_core_price_is_not_used(self):
        llama = {AERO: {"price": 0.9}, IAERO: {"price": 0.7}, LIQ: {"price": 0.02}}       # no timestamps
        out, _, logs = self.fetch(llama, {AERO: {"usd": self.AERO_PX, "last_updated_at": self.NOW - 30}})
        self.assertEqual((out[AERO.lower()]["source"], out[AERO.lower()]["priceUsd"]), ("coingecko", self.AERO_PX))
        self.assertEqual(out[IAERO.lower()]["source"], "route")
        self.assertEqual(out[LIQ.lower()]["source"], "llama")                               # not a core token
        self.assertIn(f"DefiLlama price of core token {IAERO.lower()} is undated; not used", logs)

    def test_missing_everywhere_and_no_route_leaves_iaero_unpriced(self):
        del self.chain.cl[cs(price_fetcher.IAERO_CL_POOL)]                                 # route pool unreadable
        out, pf, logs = self.fetch(self.llama_aero(), {})
        self.assertEqual((out[IAERO.lower()]["priceUsd"], out[IAERO.lower()]["source"]), (0.0, "none"))
        self.assertNotIn(f"base:{IAERO.lower()}", pf.mem)
        self.assertIn("iAERO route: pool read failed", logs)

    def test_stale_prices_are_never_used_when_the_route_fails(self):
        self.set_pools(0.8189, 46_368, 50_000)                                             # v2 ~13% off: refused
        llama = {**self.llama_aero(), IAERO: {"price": 0.6656, "timestamp": self.NOW - 9 * 3600}}
        out, pf, _ = self.fetch(llama, {IAERO: {"usd": 0.499549, "last_updated_at": 1793402249}})
        self.assertEqual((out[IAERO.lower()]["priceUsd"], out[IAERO.lower()]["source"]), (0.0, "none"))
        self.assertNotIn(f"base:{IAERO.lower()}", pf.mem)
        self.assertEqual(out[AERO.lower()]["source"], "llama")


if __name__ == "__main__":
    unittest.main()
