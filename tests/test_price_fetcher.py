# test_price_fetcher.py
# Unit tests for the on-chain DEX fallback in PriceFetcher (deepest Aero / Aerodrome pool, ~$10 quote).
# Uses a fake in-memory web3; no network. Run: python -m unittest discover -s tests
import json
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


class Reverted(Exception):
    pass


class FakeChain:
    """Minimal model of Aero (getPool(a,b)) and Aerodrome (getPool(a,b,bool)) factories + v2 pools."""

    def __init__(self):
        self.aero = {cs(AERO_VOLATILE_FACTORY): {}, cs(AERO_STABLE_FACTORY): {}}
        self.aerodrome = {cs(AERODROME_FACTORY): {}}
        self.pools = {}  # pool -> {token: reserve}
        self.decimals = {USDC: 6, WETH: 18, AERO: 18, OLD_AERO: 18, LIQ: 18}
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
        if address in self.pools and name in ("token0", "getReserves"):
            t0, t1 = sorted(self.pools[address], key=str.lower)        # pools order their tokens by address
            return t0 if name == "token0" else [self.pools[address][t0], self.pools[address][t1], 0]
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


if __name__ == "__main__":
    unittest.main()
