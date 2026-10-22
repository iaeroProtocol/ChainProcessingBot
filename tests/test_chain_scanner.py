# test_chain_scanner.py
# ChainScanner.reward_funded_events / block_at_or_before (the rolling APY's event reader). Fake web3; no network.
# Run: python -m unittest discover -s tests
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from hexbytes import HexBytes  # noqa: E402
from web3 import Web3  # noqa: E402

import chain_scanner  # noqa: E402

DIST = "0x781A80fA817b5a146C440F03EF8643f4aca6588A"
USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
LATEST, LATEST_TS = 10_000_000, 1_793_000_000


class FakeChain:
    """Blocks every `block_time` seconds up to LATEST; RewardFunded logs at given blocks; get_logs may fail above a range."""

    def __init__(self, block_time, logs, max_range=None):
        self.block_time, self.logs, self.max_range, self.log_calls = block_time, logs, max_range, []
        self.eth = mock.Mock(block_number=LATEST)
        self.eth.get_block.side_effect = self.get_block
        self.eth.get_logs.side_effect = self.get_logs

    to_checksum_address = staticmethod(Web3.to_checksum_address)

    def ts(self, b):
        return int(LATEST_TS - (LATEST - b) * self.block_time)

    def get_block(self, b):
        b = LATEST if b == "latest" else b
        return {"number": b, "timestamp": self.ts(b)}

    def get_logs(self, flt):
        fb, tb = flt["fromBlock"], flt["toBlock"]
        self.log_calls.append((fb, tb))
        if self.max_range is not None and tb - fb + 1 > self.max_range:
            raise Exception("query exceeds max block range")
        assert flt["topics"] == [chain_scanner.REWARDFUNDED_TOPIC] and flt["address"] == Web3.to_checksum_address(DIST)
        return [lg for lg in self.logs if fb <= lg["blockNumber"] <= tb]


def _log(block, token, epoch, amount):
    return {"blockNumber": block, "topics": [HexBytes(chain_scanner.REWARDFUNDED_TOPIC),
                                             HexBytes(bytes(12) + bytes.fromhex(token[2:])),
                                             HexBytes(epoch.to_bytes(32, "big"))],
            "data": HexBytes(amount.to_bytes(32, "big"))}


def _scanner(chain):
    s = chain_scanner.ChainScanner.__new__(chain_scanner.ChainScanner)
    s.w3 = chain
    return s


class RewardFundedEventsTest(unittest.TestCase):
    def test_block_lookup_does_not_trust_2s_blocks(self):
        for bt in (2.0, 0.2):                                     # Base today, and with 200 ms blocks
            chain = FakeChain(bt, [])
            target = LATEST_TS - 7 * 86400
            b = _scanner(chain).block_at_or_before(target)
            self.assertLessEqual(chain.ts(b), target)
            self.assertGreater(chain.ts(b), target - 7 * 86400)   # not far beyond what is needed
        self.assertEqual(_scanner(FakeChain(2.0, [])).block_at_or_before(LATEST_TS + 5), LATEST)

    def test_events_parsed_and_filtered_by_block_time(self):
        chain = FakeChain(2.0, [])
        frm, to = LATEST_TS - 3 * 86400, LATEST_TS - 86400
        b_in, b_out, b_late = LATEST - 2 * 43_200 + 10, LATEST - 3 * 43_200 - 10, LATEST - 100
        chain.logs = [_log(b_in, USDC, 1792627200, 1_234 * 10**6), _log(b_out, USDC, 1792627200, 1),
                      _log(b_late, USDC, 1793232000, 2)]
        ev = _scanner(chain).reward_funded_events(DIST, frm, to)
        self.assertEqual(ev, [{"token": USDC, "epoch": 1792627200, "amount": 1_234 * 10**6, "timestamp": chain.ts(b_in),
                               "blockNumber": b_in}])

    def test_range_errors_shrink_the_step_and_a_gap_raises(self):
        chain = FakeChain(2.0, [], max_range=2_000)
        ev = _scanner(chain).reward_funded_events(DIST, LATEST_TS - 86400, LATEST_TS)
        self.assertEqual(ev, [])
        self.assertTrue(all(tb - fb + 1 <= 10_000 for fb, tb in chain.log_calls))
        covered = sorted((fb, tb) for fb, tb in chain.log_calls if tb - fb + 1 <= 2_000)
        self.assertEqual(covered[-1][1], LATEST)                  # scanned to the tip
        with self.assertRaises(Exception):                        # a range it can never read: raise, not skip
            _scanner(FakeChain(2.0, [], max_range=100)).reward_funded_events(DIST, LATEST_TS - 86400, LATEST_TS)

    def test_rate_limit_is_retried(self):
        chain = FakeChain(2.0, [_log(LATEST - 10, USDC, 1792627200, 5)])
        real, calls = chain.get_logs, {"n": 0}

        def flaky(flt):
            calls["n"] += 1
            if calls["n"] <= 2:
                raise Exception("429 Client Error: Too Many Requests")
            return real(flt)
        chain.eth.get_logs.side_effect = flaky
        with mock.patch.object(chain_scanner.time, "sleep") as sl:
            ev = _scanner(chain).reward_funded_events(DIST, LATEST_TS - 3600, LATEST_TS)
        self.assertEqual(([e["amount"] for e in ev], sl.call_count), ([5], 2))


if __name__ == "__main__":
    unittest.main()
