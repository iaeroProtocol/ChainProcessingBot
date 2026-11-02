"""PR #6 follow-up controls for CPB-PR6-M01/L01/L02. All chain/publication data are simulated."""
import json
import os
import sys
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import main
import position_earnings as pe
from github_updater import GitHubUpdater
from test_measured_headline import World, RUN0, DAY, LS, EST, daily_harvests, daily_fundings
from test_processing_upgrade import MemoryGit
from test_position_earnings import USDC


class PublishingGit(MemoryGit):
    def __init__(self, files):
        super().__init__()
        self.revisions["base"] = dict(files)
        self.fail = {}

    @property
    def files(self):
        return self.revisions[self.head]

    def get_contents(self, path, ref=None):
        if path in self.fail:
            raise self.fail[path]
        return super().get_contents(path, ref)

    def update_file(self, path, message, content, sha, branch):
        # Support the reviewed version's one-file index publisher too, so baseline controls fail on data behaviour.
        if self.get_contents(path, ref=branch).sha != sha:
            raise RuntimeError("concurrent update")
        parent = self.get_git_commit(self.head)
        tree = dict(parent.tree)
        tree[path] = content
        commit = self.create_git_commit(message, tree, [parent])
        self.get_git_ref("heads/" + branch).edit(commit.sha, force=False)


def publishing_world():
    world = World(harvests=daily_harvests(last_day=40), fundings=daily_fundings(last_day=40))
    world.repo = PublishingGit(world.repo.files)
    world.updater = GitHubUpdater(None, "simulated", repo=world.repo)
    for day in range(9):
        world.run(RUN0 + day * DAY)
    return world


class CorePublicationIsolation(unittest.TestCase):
    def test_secondary_index_read_failure_still_commits_fresh_core_as_one_generation(self):
        world = publishing_world()
        prior_state = world.repo.files[LS]
        prior_forecast = world.repo.files[EST]
        commits = len(world.repo.edits)
        world.repo.fail["data/epochs.json"] = RuntimeError("secondary API unavailable")
        doc = world.run(RUN0 + 9 * DAY)
        self.assertEqual(len(world.repo.edits), commits + 1)
        self.assertNotEqual(world.repo.files[LS], prior_state)
        self.assertNotEqual(world.repo.files[EST], prior_forecast)
        self.assertEqual(doc["apySource"], "measured-7d")
        self.assertFalse(doc["stale"])
        self.assertNotIn("fundedRealized", doc)
        self.assertEqual(doc["fundedRealizedStatus"], "unavailable")
        state = json.loads(world.repo.files[LS])
        self.assertEqual(doc["measurementGeneration"], state["generation"])
        self.assertTrue(state["history"][-1]["complete"])


class ReplayInvalidation(unittest.TestCase):
    def test_known_orphan_remains_invalid_after_replay_failure_and_restart(self):
        world = publishing_world()
        original_forecast = world.repo.files[EST]
        state = json.loads(world.repo.files[LS])
        state["chains"]["8453"]["blockHash"] = "0x" + "ff" * 32
        world.repo.files[LS] = json.dumps(state)
        original_rows = pe._gauge_rows
        def rows(reader, *args, **kwargs):
            if reader.chain_id == 8453:
                raise RuntimeError("replay calls failed")
            return original_rows(reader, *args, **kwargs)
        with mock.patch.object(pe, "_gauge_rows", side_effect=rows):
            doc = world.run(RUN0 + 9 * DAY)
        self.assertIsNone(doc["apyPct"])
        self.assertIsNone(doc["estimatedWeeklyUSD_1e18"])
        saved = json.loads(world.repo.files[LS])
        self.assertTrue(saved["chains"]["8453"]["invalidated"])
        self.assertNotIn("vrms", saved["chains"]["8453"])
        self.assertFalse(any(point["complete"] for point in saved["history"]))
        # Model a restart with an old public figure still present (e.g. the public output was disabled).
        world.repo.files[EST] = original_forecast
        with mock.patch.object(pe, "_gauge_rows", side_effect=rows):
            doc = world.run(RUN0 + 10 * DAY)
        self.assertIsNone(doc["apyPct"])
        self.assertTrue(json.loads(world.repo.files[LS])["chains"]["8453"]["invalidated"])
        world.run(RUN0 + 11 * DAY)
        repaired = json.loads(world.repo.files[LS])
        self.assertNotIn("invalidated", repaired["chains"]["8453"])
        self.assertTrue(repaired["history"][-1]["complete"])
        self.assertEqual(len(repaired["history"]), 1)


def block_hash(number, fork=False):
    return "0x" + format(number + (1_000_000 if fork and number >= 90 else 0), "064x")


class FundingScanner:
    chain_id = 8453
    def __init__(self, tip=110, fork=True, fail=False):
        self.tip, self.fork, self.fail = tip, fork, fail
        self.calls = []
        self.events = [(20, 1, "0x" + "22" * 20), (95, 2, "0x" + "33" * 20)]

    def latest_block(self):
        return self.tip

    def block_hash(self, number):
        return block_hash(number, self.fork)

    def block_timestamp(self, number):
        return RUN0 + 10 * DAY

    def funded_epochs_and_tokens(self, distributor, start, end):
        self.calls.append((start, end))
        if self.fail:
            raise RuntimeError("replay range unavailable")
        out = defaultdict(set)
        for block, epoch, token in self.events:
            if start <= block <= end:
                out[epoch].add(token)
        return sorted(out), {epoch: sorted(tokens) for epoch, tokens in out.items()}


class FundingIndexFixture(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"EPOCH_STAKING_DISTRIBUTOR": USDC, "EPOCHS_START_BLOCK": "10"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.path = "data/epochs.json"
        self.old = {"distributorAddress": USDC, "epochs": {
            "1": {"tokens": ["0x" + "22" * 20]}, "2": {"tokens": ["0x" + "44" * 20]}},
            "state": {"version": 2, "last_block": 100, "last_block_hash": block_hash(100),
                      "last_block_timestamp": RUN0 + 10 * DAY,
                      "start_block": 10, "start_block_hash": block_hash(10)}}
        self.repo = PublishingGit({self.path: json.dumps(self.old)})
        self.updater = GitHubUpdater(None, "simulated", repo=self.repo)


class FundingIndexReorg(FundingIndexFixture):
    def test_orphaned_entries_are_removed_and_replacement_events_replayed(self):
        scanner = FundingScanner()
        main._update_epochs(self.repo, self.updater, scanner)
        doc = json.loads(self.repo.files[self.path])
        self.assertEqual(doc["epochs"]["2"]["tokens"], ["0x" + "33" * 20])
        self.assertEqual(doc["epochs"]["1"], self.old["epochs"]["1"])
        self.assertEqual(scanner.calls, [(10, 110)])
        self.assertEqual(doc["state"]["last_block_hash"], scanner.block_hash(110))
        scanner.tip = 120
        main._update_epochs(self.repo, self.updater, scanner)
        self.assertEqual(scanner.calls[-1], (111, 120))

    def test_reorg_at_the_saved_height_is_not_mistaken_for_up_to_date(self):
        scanner = FundingScanner(tip=100)
        main._update_epochs(self.repo, self.updater, scanner)
        self.assertEqual(scanner.calls, [(10, 100)])
        self.assertEqual(json.loads(self.repo.files[self.path])["epochs"]["2"]["tokens"], ["0x" + "33" * 20])



class OptionalFailureVariants(unittest.TestCase):
    def test_secondary_bad_json_and_invalid_checkpoint_cannot_discard_core(self):
        import base64
        from types import SimpleNamespace
        for failure in ("bad_json", "orphaned_checkpoint", "index_before_epoch_end"):
            with self.subTest(failure=failure):
                world = publishing_world()
                original_get = world.repo.get_contents
                def get(path, ref=None):
                    if path != "data/epochs.json":
                        return original_get(path, ref)
                    if failure == "bad_json":
                        value = "not JSON"
                    else:
                        value = json.loads(world.repo.files[path])
                        if failure == "orphaned_checkpoint":
                            value["state"]["last_block_hash"] = "0x" + "ff" * 32
                        else:
                            value["state"]["last_block_timestamp"] = RUN0 - 10 * DAY
                        value = json.dumps(value)
                    return SimpleNamespace(encoding="base64", content=base64.b64encode(value.encode()).decode())
                commits = len(world.repo.edits)
                with mock.patch.object(world.repo, "get_contents", side_effect=get):
                    doc = world.run(RUN0 + 9 * DAY)
                self.assertFalse(doc["stale"])
                self.assertEqual(doc["fundedRealizedStatus"], "unavailable")
                self.assertNotIn("fundedRealized", doc)
                self.assertEqual(len(world.repo.edits), commits + 1)
                self.assertEqual(doc["measurementGeneration"], json.loads(world.repo.files[LS])["generation"])


class InvalidationFailureVariants(unittest.TestCase):
    def test_invalidation_precedes_the_first_replay_multicall(self):
        from test_measured_headline import SimReader
        world = publishing_world()
        state = json.loads(world.repo.files[LS])
        state["chains"]["8453"]["blockHash"] = "0x" + "ff" * 32
        world.repo.files[LS] = json.dumps(state)
        original = SimReader.many
        def many(reader, calls):
            if reader.chain_id == 8453 and calls and calls[0][1] == "allocatedGauges(uint256)":
                raise RuntimeError("first replay call failed")
            return original(reader, calls)
        with mock.patch.object(SimReader, "many", many):
            doc = world.run(RUN0 + 9 * DAY)
        self.assertIsNone(doc["apyPct"])
        self.assertTrue(json.loads(world.repo.files[LS])["chains"]["8453"]["invalidated"])

    def test_pending_invalidation_survives_disabled_output_then_failed_measurement(self):
        world = publishing_world()
        original_public = world.repo.files[EST]
        state = json.loads(world.repo.files[LS])
        state["chains"]["8453"]["blockHash"] = "0x" + "ff" * 32
        world.repo.files[LS] = json.dumps(state)
        original_rows = pe._gauge_rows
        def rows(reader, *args, **kwargs):
            if reader.chain_id == 8453:
                raise RuntimeError("replay failed")
            return original_rows(reader, *args, **kwargs)
        with mock.patch.object(pe, "_gauge_rows", side_effect=rows):
            world.run(RUN0 + 9 * DAY, env={"ESTIMATED_REWARDS_ENABLED": "false"})
        self.assertEqual(world.repo.files[EST], original_public)
        pending = json.loads(world.repo.files[LS])
        self.assertTrue(pending["chains"]["8453"]["invalidated"])
        world.base_pf.prices = {}
        with mock.patch.object(main, "_build_live_block", side_effect=RuntimeError("measurement unavailable before replay")):
            doc = world.run(RUN0 + 10 * DAY)
        self.assertIsNone(doc["apyPct"])
        self.assertIsNone(doc["estimatedWeeklyUSD_1e18"])
        self.assertEqual(doc["measurementGeneration"], pending["generation"])


class FundingIndexFailureVariants(FundingIndexFixture):
    def test_failed_replay_retains_the_previous_file_and_does_not_advance(self):
        before = self.repo.files[self.path]
        with self.assertRaises(RuntimeError):
            main._update_epochs(self.repo, self.updater, FundingScanner(fail=True))
        self.assertEqual(self.repo.files[self.path], before)
        self.assertEqual(self.repo.edits, [])

    def test_legacy_height_only_index_is_rebuilt_instead_of_blessing_old_entries(self):
        self.old["state"].pop("last_block_hash")
        self.repo.files[self.path] = json.dumps(self.old)
        scanner = FundingScanner(fork=False)
        main._update_epochs(self.repo, self.updater, scanner)
        doc = json.loads(self.repo.files[self.path])
        self.assertEqual(scanner.calls, [(10, 110)])
        self.assertEqual(doc["epochs"]["2"]["tokens"], ["0x" + "33" * 20])
        self.assertEqual(doc["state"]["version"], 2)

    def test_changed_tip_during_replay_is_not_published(self):
        scanner = FundingScanner()
        original_hash = scanner.block_hash
        count = 0
        def changing(number):
            nonlocal count
            if number == scanner.tip:
                count += 1
                if count > 1:
                    return "0x" + "ee" * 32
            return original_hash(number)
        scanner.block_hash = changing
        before = self.repo.files[self.path]
        with self.assertRaisesRegex(RuntimeError, "tip changed"):
            main._update_epochs(self.repo, self.updater, scanner)
        self.assertEqual(self.repo.files[self.path], before)
        self.assertEqual(self.repo.edits, [])

    def test_unknown_anchor_is_not_silently_replaced(self):
        with mock.patch.dict(os.environ, {"EPOCHS_START_BLOCK_HASH": "0x" + "ff" * 32}):
            with self.assertRaisesRegex(RuntimeError, "anchor"):
                main._update_epochs(self.repo, self.updater, FundingScanner())
        self.assertEqual(self.repo.edits, [])

    def test_lagging_provider_cannot_reset_the_index(self):
        before = self.repo.files[self.path]
        with self.assertRaisesRegex(RuntimeError, "behind"):
            main._update_epochs(self.repo, self.updater, FundingScanner(tip=99))
        self.assertEqual(self.repo.files[self.path], before)

    def test_known_production_distributor_has_a_checked_default_anchor(self):
        (chain, address), (start, expected_hash) = next(iter(main._EPOCH_DEPLOYMENTS.items()))
        self.repo.files[self.path] = json.dumps({"epochs": {}})
        scanner = FundingScanner(tip=start + 10)
        original_hash = scanner.block_hash
        scanner.block_hash = lambda number: expected_hash if number == start else original_hash(number)
        with mock.patch.dict(os.environ, {"EPOCH_STAKING_DISTRIBUTOR": address}):
            os.environ.pop("EPOCHS_START_BLOCK", None)
            main._update_epochs(self.repo, self.updater, scanner)
        doc = json.loads(self.repo.files[self.path])
        self.assertEqual(scanner.calls, [(start, start + 10)])
        self.assertEqual(doc["state"]["start_block_hash"], expected_hash)



class CoreSchedulingAndSnapshot(unittest.TestCase):
    def test_funding_repair_deadline_occurs_after_the_core_publication(self):
        from job_runtime import JobDeadlineExceeded
        order = []
        def core(*args):
            order.append("core")
            return True
        def repair(*args):
            order.append("funding repair")
            raise JobDeadlineExceeded("bounded repair")
        with mock.patch.dict(os.environ, {"BASE_RPC_URL": "http://fake", "GITHUB_TOKEN": "fake",
                "GITHUB_REPO": "org/repo", "EPOCH_STAKING_DISTRIBUTOR": USDC}, clear=True), \
             mock.patch.object(main, "load_dotenv"), mock.patch.object(main, "Github"), \
             mock.patch.object(main, "GitHubUpdater", return_value=mock.Mock(measurement_status="fresh")), \
             mock.patch.object(main, "ChainScanner"), mock.patch.object(main, "PriceFetcher"), \
             mock.patch.object(main, "_update_realized_yield", side_effect=core), \
             mock.patch.object(main, "_update_epochs", side_effect=repair), self.assertRaises(JobDeadlineExceeded):
            main._run_once()
        self.assertEqual(order, ["core", "funding repair"])

    def test_funding_amounts_use_the_same_block_as_the_token_index(self):
        import realized_yield as ry
        w3 = mock.Mock()
        w3.to_checksum_address.side_effect = lambda a: a
        call = w3.eth.contract.return_value.functions.rewardsForEpoch.return_value.call
        call.side_effect = lambda block_identifier=None: 25 if block_identifier == 50 else 999
        def value(w3, distributor, raw, *args):
            return raw
        with mock.patch.object(ry, "_price_and_compute", side_effect=value), mock.patch.object(ry, "_log_payload"):
            result = ry.build_estimated_rewards(w3, USDC, {"epochs": {"12": {"tokens": [USDC]}}},
                mock.Mock(), mock.Mock(), epoch=12, funding_block=50)
        self.assertEqual(result[USDC], 25)
        call.assert_called_once_with(block_identifier=50)
