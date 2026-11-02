"""CPB-PR6-FIX-L01: post-valuation canonical checks affect only the secondary attachment."""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import main
import realized_yield as ry
from test_pr6_followup import publishing_world, RUN0, DAY, LS


class SecondaryFundingCanonicalCheck(unittest.TestCase):
    def run_valuation(self, result):
        world = publishing_world()
        previous_rate = json.loads(world.repo.files["data/estimated_rewards_usd.json"])["apyPct"]
        commits = len(world.repo.edits)
        progress = {"valued": False}
        original_update = main._update_realized_yield
        original_build = ry.build_estimated_rewards

        def update(repo, updater, scanner, price_fetcher):
            def canonical_hash(number):
                if progress["valued"]:
                    if result == "reorg":
                        return "0x" + "ff" * 32
                    if result == "unreadable":
                        raise RuntimeError("post-valuation hash unavailable")
                return "0x" + format(int(number), "064x")
            scanner.block_hash.side_effect = canonical_hash
            return original_update(repo, updater, scanner, price_fetcher)

        def value(*args, **kwargs):
            values = original_build(*args, **kwargs)
            progress["valued"] = True
            return values

        with mock.patch.object(main, "_update_realized_yield", side_effect=update), \
             mock.patch.object(ry, "build_estimated_rewards", side_effect=value):
            doc = world.run(RUN0 + 9 * DAY)
        self.assertTrue(progress["valued"])
        self.assertEqual(len(world.repo.edits), commits + 1)
        self.assertEqual(doc["apySource"], "measured-7d")
        self.assertAlmostEqual(doc["apyPct"], previous_rate, places=9)
        self.assertFalse(doc["stale"])
        self.assertTrue(doc["live"]["readComplete"])
        state = json.loads(world.repo.files[LS])
        self.assertTrue(state["history"][-1]["complete"])
        self.assertEqual(doc["measurementGeneration"], state["generation"])
        self.assertEqual(world.updater.measurement_status, "fresh")
        return doc

    def test_reorg_during_valuation_omits_attachment_and_preserves_core(self):
        doc = self.run_valuation("reorg")
        self.assertEqual(doc["fundedRealizedStatus"], "unavailable")
        self.assertNotIn("fundedRealized", doc)

    def test_failed_post_valuation_hash_read_omits_attachment_and_preserves_core(self):
        doc = self.run_valuation("unreadable")
        self.assertEqual(doc["fundedRealizedStatus"], "unavailable")
        self.assertNotIn("fundedRealized", doc)

    def test_stable_canonical_block_keeps_the_attachment(self):
        doc = self.run_valuation("stable")
        self.assertEqual(doc["fundedRealizedStatus"], "available")
        attachment = doc["fundedRealized"]
        self.assertEqual(attachment["asOfBlock"], 1)
        self.assertEqual(attachment["asOfBlockHash"], "0x" + format(1, "064x"))
