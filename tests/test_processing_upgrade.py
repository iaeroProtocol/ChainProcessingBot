"""Offline regression controls for the processing upgrade; no RPC or publisher execution."""
import base64
import copy
import hashlib
import io
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import main
import position_earnings as pe
from github_updater import GitHubUpdater
from job_runtime import JobDeadlineExceeded, job_deadline, redact_value
from chain_scanner import ChainScanner
from price_fetcher import PriceFetcher
from test_measured_headline import World, RUN0, DAY, LS, EST, daily_harvests, daily_fundings
from test_position_earnings import (BlockLogsReader, FEE_USDC, base_answers, VRM_V2, USDC, META, PRICES,
                                   T0, NOW, G_CL, E18, _chain, _g2)


class ColdStartRecovery(unittest.TestCase):
    def test_late_cold_start_survives_daily_restarts_without_a_headline(self):
        w = World(prev=False, harvests=daily_harvests(last_day=30), fundings=daily_fundings(last_day=30))
        for d in range(9):
            doc = w.run(RUN0 + (10 + d) * DAY)
            saved = json.loads(w.repo.files[LS])
            self.assertTrue(saved["history"])
            self.assertEqual(saved["version"], 2)
            # Lose all in-process state: only independently persisted inputs survive.
            w.repo.files = json.loads(json.dumps(w.repo.files))
            if d < 6:
                self.assertIsNone(doc)
        self.assertEqual(doc["apySource"], "measured-7d")
        self.assertFalse(doc["stale"])
        self.assertTrue(doc["live"]["readComplete"])

    def test_unreadable_measurement_state_is_not_treated_as_a_cold_start(self):
        w = World()
        w.run(RUN0)
        before = w.repo.files[LS]
        w.repo.fail[LS] = RuntimeError("503")
        with self.assertRaises(RuntimeError):
            w.run(RUN0 + DAY)
        self.assertEqual(w.repo.files[LS], before)

    def test_failed_state_write_cannot_publish_a_new_headline(self):
        w = World()
        w.run(RUN0)
        before = w.repo.files[EST]
        original = w.updater.update_file
        def fail(path, *args, **kwargs):
            if path == LS:
                raise RuntimeError("write unavailable")
            return original(path, *args, **kwargs)
        with mock.patch.object(w.updater, "update_file", side_effect=fail), self.assertRaises(RuntimeError):
            w.run(RUN0 + DAY)
        self.assertEqual(w.repo.files[EST], before)


class CanonicalClaims(unittest.TestCase):
    def read(self, reader, state=None):
        return pe.read_chain_position(reader, 1584, registry=pe.FACTORY_REGISTRY_BASE, claims_state=state)

    def test_orphaned_claim_is_removed_and_matches_a_clean_canonical_scan(self):
        a = BlockLogsReader(base_answers(), [(950, FEE_USDC(100 * 10**6))])
        old = self.read(a)["claimsState"]
        self.assertEqual(old["vrms"][VRM_V2]["fees"][USDC], 100 * 10**6)

        class Fork(BlockLogsReader):
            def block_hash(self, block):
                return "0x" + format(int(block) + 1000000, "064x")
        restored = base_answers()
        for cap in (10000, 20000):
            restored[(VRM_V2, "earnedFees(uint256,uint256)", (1584, cap))] = (10 * E18, 110 * 10**6)
        b = Fork(restored, [], block=1100)
        resumed = self.read(b, old)
        clean = self.read(Fork(restored, [], block=1100))
        self.assertTrue(resumed["historyReset"])
        self.assertEqual(resumed["claimsState"]["vrms"], clean["claimsState"]["vrms"])
        self.assertEqual(resumed["gauges"], clean["gauges"])
        self.assertEqual(old["vrms"][VRM_V2]["fees"][USDC], 100 * 10**6)
        self.assertEqual(b.log_calls[0][2], 10)

    def test_legacy_hashless_totals_are_rebuilt_once(self):
        r = BlockLogsReader(base_answers(), [])
        old = self.read(r)["claimsState"]
        old.pop("blockHash")
        old["vrms"][VRM_V2]["fees"][USDC] = 999 * 10**6
        out = self.read(BlockLogsReader(base_answers(), [], block=1100), old)
        self.assertTrue(out["historyReset"])
        self.assertNotIn(USDC, out["claimsState"]["vrms"][VRM_V2]["fees"])
        next_read = self.read(BlockLogsReader(base_answers(), [], block=1200), out["claimsState"])
        self.assertFalse(next_read["historyReset"])

    def test_hash_read_failure_does_not_mutate_a_checkpoint(self):
        r = BlockLogsReader(base_answers(), [])
        state = self.read(r)["claimsState"]
        before = copy.deepcopy(state)
        r.block_hash = mock.Mock(side_effect=RuntimeError("provider unavailable"))
        with self.assertRaises(RuntimeError):
            self.read(r, state)
        self.assertEqual(state, before)

    def test_reorg_during_a_measurement_is_refused(self):
        r = BlockLogsReader(base_answers(), [])
        r.block_hash = mock.Mock(side_effect=["0x" + "aa" * 32, "0x" + "bb" * 32])
        with self.assertRaisesRegex(ValueError, "changed during"):
            self.read(r)


class VerifiedUnits(unittest.TestCase):
    def live(self, amount, now, history=(), decimals=6):
        meta = copy.deepcopy(META)
        meta[8453][USDC]["decimals"] = decimals
        return pe.value_live([_chain(8453, T0, now, E18, [_g2(G_CL, fees={USDC: amount})])],
                             meta, PRICES, 1584, 1_000_000 * E18, .8, 600_000,
                             now_ts=now, prev_history=list(history))

    def test_unknown_decimals_cannot_make_a_complete_point_or_artificial_income(self):
        first = self.live(100 * 10**6, NOW, decimals=None)
        self.assertFalse(first["readComplete"])
        self.assertEqual(first["unknownMetadata"], ["8453:" + USDC])
        self.assertEqual(first["history"][0]["gauges"]["8453:" + G_CL]["rawFees"][USDC], "100000000")
        second = self.live(110 * 10**6, NOW + DAY, first["history"])
        self.assertIsNone(second["trailing"]["24h"])
        third = self.live(120 * 10**6, NOW + 2 * DAY, second["history"])
        self.assertAlmostEqual(third["trailing"]["24h"]["usdPerDay"], 10.0)
        self.assertTrue(third["trailing"]["24h"]["complete"])

    def test_changed_verified_units_are_not_counted_as_revenue(self):
        first = self.live(100 * 10**6, NOW, decimals=18)
        second = self.live(110 * 10**6, NOW + DAY, first["history"])
        self.assertFalse(second["trailing"]["24h"]["complete"])
        self.assertTrue(second["trailing"]["24h"]["partial"])

    def test_raw_integer_history_preserves_small_changes_in_large_balances(self):
        first = self.live(10**30, NOW)
        second = self.live(10**30 + 1, NOW + DAY, first["history"])
        self.assertAlmostEqual(second["trailing"]["24h"]["usdPerDay"], .000001, places=12)

    def test_zero_decimals_are_valid(self):
        first = self.live(100, NOW, decimals=0)
        second = self.live(110, NOW + DAY, first["history"], decimals=0)
        self.assertTrue(second["readComplete"])
        self.assertAlmostEqual(second["trailing"]["24h"]["usdPerDay"], 10)

    def test_legacy_complete_flag_cannot_promote_human_only_history(self):
        old = {"asOf": NOW, "complete": True, "chains": [8453], "gauges": {}}
        second = self.live(110 * 10**6, NOW + 7 * DAY, [old])
        self.assertIsNone(second["trailing"]["7d"])
        self.assertEqual(len(second["history"]), 1)

    def test_failed_metadata_read_remains_unknown(self):
        r = mock.Mock()
        r.many.return_value = ["USDC", None]
        self.assertIsNone(pe.token_meta(r, [USDC])[USDC]["decimals"])


class ComputeAndScanControls(unittest.TestCase):
    def test_default_job_does_not_load_or_export_wallet_matrix_or_need_explorer(self):
        scanner = mock.Mock()
        with mock.patch.dict(os.environ, {"BASE_RPC_URL": "http://fake", "GITHUB_TOKEN": "fake",
                "GITHUB_REPO": "org/repo", "EPOCH_STAKING_DISTRIBUTOR": USDC}, clear=True), \
             mock.patch.object(main, "load_dotenv"), mock.patch.object(main, "Github"), \
             mock.patch.object(main, "GitHubUpdater"), mock.patch.object(main, "ChainScanner", return_value=scanner), \
             mock.patch.object(main, "PriceFetcher"), mock.patch.object(main, "_update_epochs", return_value=False), \
             mock.patch.object(main, "_update_realized_yield", return_value=True), \
             mock.patch.object(main, "_update_stakers") as holders, \
             mock.patch.object(main, "_update_staker_rewards") as export, \
             mock.patch.object(main, "load_last_state_from_github") as legacy:
            self.assertTrue(main._run_once())
        holders.assert_not_called()
        export.assert_not_called()
        legacy.assert_not_called()
        scanner.check_for_new_incoming_erc20.assert_not_called()
        scanner.check_for_new_outgoing_erc20.assert_not_called()

    def test_log_failure_never_skips_an_unread_slice(self):
        scanner = object.__new__(ChainScanner)
        scanner.w3 = mock.Mock()
        scanner.w3.to_checksum_address.side_effect = lambda a: a
        scanner.w3.eth.get_logs.side_effect = RuntimeError("provider failure")
        with self.assertRaisesRegex(RuntimeError, "Unscanned"):
            list(scanner._get_logs_chunked(USDC, [], 100, 300, step=1000))

    def test_price_miss_is_briefly_memoised_without_caching_a_zero_price(self):
        with tempfile.TemporaryDirectory() as d:
            pf = PriceFetcher(cache_file=os.path.join(d, "p.json"))
            with mock.patch.object(pf, "_fetch_llama", return_value={}) as ll, \
                 mock.patch.object(pf, "_fetch_coingecko", return_value={}), \
                 mock.patch.object(pf, "_fetch_dex", return_value={}), \
                 mock.patch("price_fetcher._now", return_value=1000):
                pf.fetch_batch([USDC])
                pf.fetch_batch([USDC])
                self.assertEqual(ll.call_count, 2)  # empty batch is cheap; no token is requested twice
                self.assertEqual(ll.call_args.args[0], [])
                self.assertNotIn(pf._key(USDC), pf.mem)
            with mock.patch.object(pf, "_fetch_llama", return_value={}) as ll, \
                 mock.patch.object(pf, "_fetch_coingecko", return_value={}), \
                 mock.patch.object(pf, "_fetch_dex", return_value={}), \
                 mock.patch("price_fetcher._now", return_value=1031):
                pf.fetch_batch([USDC])
                self.assertEqual(ll.call_args.args[0], [USDC])

    def test_unconfigured_required_chain_is_not_silently_complete(self):
        reader = BlockLogsReader(base_answers(), [])
        pf = mock.Mock()
        pf.fetch_batch.side_effect = lambda toks: {t: {"priceUsd": PRICES[8453].get(t, 0), "source": "llama"} for t in toks}
        with mock.patch.object(pe, "token_meta", return_value=META[8453]):
            out = pe.build_live([(reader, pe.FACTORY_REGISTRY_BASE)], 1584, {8453: pf}, E18, .8, 600000,
                                required_chains=[8453, 1])
        self.assertIn(1, out["unmeasuredChains"])
        self.assertFalse(out["readComplete"])




class MemoryGit:
    """A branch with immutable revisions and non-fast-forward protection."""
    def __init__(self):
        self.head = "base"
        self.revisions = {"base": {"data/a.json": "old", "code.py": "old code"}}
        self.parents = {}
        self.edits = []

    def get_contents(self, path, ref=None):
        files = self.revisions[self.head if ref in (None, "main") else ref]
        if path not in files:
            error = FileNotFoundError(path)
            raise error
        data = files[path]
        return SimpleNamespace(content=base64.b64encode(data.encode()).decode(),
                               sha=hashlib.sha256(data.encode()).hexdigest(), encoding="base64")

    def get_git_ref(self, name):
        owner = self
        class Ref:
            object = SimpleNamespace(sha=owner.head)
            def edit(self, sha, force=False):
                assert not force
                if owner.parents[sha] != owner.head:
                    error = RuntimeError("non-fast-forward")
                    error.status = 422
                    raise error
                owner.head = sha
                owner.edits.append(sha)
        return Ref()

    def get_git_commit(self, sha):
        return SimpleNamespace(sha=sha, tree=dict(self.revisions[sha]))

    def create_git_tree(self, entries, base_tree):
        tree = dict(base_tree)
        tree.update({e._identity["path"]: e._identity["content"] for e in entries})
        return tree

    def create_git_commit(self, message, tree, parents):
        sha = "commit-" + str(len(self.revisions))
        self.parents[sha] = parents[0].sha
        self.revisions[sha] = tree
        return SimpleNamespace(sha=sha)

    def concurrent(self, changes):
        self.revisions["concurrent"] = dict(self.revisions[self.head], **changes)
        self.head = "concurrent"


class PublicationControls(unittest.TestCase):
    def test_related_files_move_together_and_reads_stay_pinned(self):
        repo = MemoryGit()
        updater = GitHubUpdater(None, "unused", repo=repo)
        with updater.transaction():
            updater.update_file("data/a.json", "new")
            updater.update_file("data/state.json", "new state")
            self.assertEqual(updater.branch, "base")
            self.assertEqual(repo.head, "base")
            self.assertEqual(updater.read_text_or_none("data/a.json"), "old")
        self.assertEqual(repo.revisions[repo.head]["data/state.json"], "new state")
        self.assertEqual(repo.revisions[repo.head]["data/a.json"], "new")
        self.assertEqual(len(repo.edits), 1)
        self.assertEqual(updater.branch, "main")

    def test_failed_collection_publishes_nothing(self):
        repo = MemoryGit()
        updater = GitHubUpdater(None, "unused", repo=repo)
        with self.assertRaises(RuntimeError):
            with updater.transaction():
                updater.update_file("data/a.json", "new")
                raise RuntimeError("collection failed")
        self.assertEqual(repo.head, "base")
        self.assertEqual(updater.branch, "main")

    def test_concurrent_code_change_is_preserved(self):
        repo = MemoryGit()
        updater = GitHubUpdater(None, "unused", repo=repo)
        with updater.transaction():
            updater.update_file("data/a.json", "new")
            repo.concurrent({"code.py": "another session"})
        self.assertEqual(repo.revisions[repo.head]["code.py"], "another session")
        self.assertEqual(repo.revisions[repo.head]["data/a.json"], "new")

    def test_concurrent_measurement_is_not_overwritten(self):
        repo = MemoryGit()
        updater = GitHubUpdater(None, "unused", repo=repo)
        with self.assertRaisesRegex(RuntimeError, "Concurrent"):
            with updater.transaction():
                updater.update_file("data/a.json", "ours")
                repo.concurrent({"data/a.json": "newer measurement"})
        self.assertEqual(repo.revisions[repo.head]["data/a.json"], "newer measurement")
        self.assertEqual(repo.edits, [])

    def test_update_error_does_not_attempt_to_create_an_existing_file(self):
        repo = mock.Mock()
        repo.get_contents.return_value.sha = "sha"
        repo.update_file.side_effect = RuntimeError("503")
        updater = GitHubUpdater(None, "unused", repo=repo)
        with self.assertRaises(RuntimeError):
            updater.update_file("data/a.json", "new")
        repo.create_file.assert_not_called()

    def test_large_state_is_read_from_its_exact_blob(self):
        repo = mock.Mock()
        repo.get_contents.return_value = SimpleNamespace(encoding="none", sha="blob")
        repo.get_git_blob.return_value.content = base64.b64encode(b'{"version":2}').decode()
        self.assertEqual(main._load_json_strict(repo, "revision", "data/live_state.json"), {"version": 2})
        repo.get_git_blob.assert_called_once_with("blob")

    def test_malformed_state_is_not_overwritten(self):
        repo = MemoryGit()
        updater = mock.Mock(branch="main")
        repo.revisions["base"]["data/a.json"] = "invalid json"
        with self.assertRaises(ValueError):
            main._push_if_changed(repo, updater, "data/a.json", {"replacement": True})
        updater.update_json.assert_not_called()


class RuntimeControls(unittest.TestCase):
    def test_deadline_escapes_phase_exception_handlers(self):
        previous = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(JobDeadlineExceeded):
            with job_deadline(10):
                try:
                    signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
                except Exception:
                    self.fail("The job deadline was swallowed")
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

    def test_status_http_is_disabled_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(main, "HTTPServer") as server:
            main._start_status_server()
        server.assert_not_called()

    def handler(self, path, auth=None):
        h = object.__new__(main._StatusHandler)
        h.path, h.headers, h.wfile = path, {"Authorization": auth or ""}, io.BytesIO()
        h.send_error, h.send_response = mock.Mock(), mock.Mock()
        h.send_header, h.end_headers = mock.Mock(), mock.Mock()
        return h

    def test_detailed_status_requires_a_configured_bearer_token(self):
        with mock.patch.dict(os.environ, {"STATUS_TOKEN": "expected"}):
            h = self.handler("/status", "Bearer wrong")
            h.do_GET()
            h.send_error.assert_called_once_with(403)
            self.assertEqual(h.wfile.getvalue(), b"")
            h = self.handler("/status", "Bearer expected")
            h.do_GET()
            self.assertIn("log", json.loads(h.wfile.getvalue()))

    def test_public_health_never_returns_the_event_log(self):
        h = self.handler("/health")
        h.do_GET()
        self.assertEqual(set(json.loads(h.wfile.getvalue())), {"process", "phase"})

    def test_redaction_handles_nested_values_without_breaking_quotes(self):
        value = {"error": 'https://provider.example/secret?key=private\\\"tail', "nested": ["Bearer private", 5]}
        out = redact_value(value)
        self.assertNotIn("provider.example", json.dumps(out))
        self.assertNotIn("private", json.dumps(out))
        self.assertEqual(out["nested"][1], 5)


class MigrationAndCursorControls(unittest.TestCase):
    def test_reorg_invalidates_previous_public_income_then_recovers_from_independent_history(self):
        w = World(harvests=daily_harvests(last_day=40), fundings=daily_fundings(last_day=40))
        for d in range(9):
            before = w.run(RUN0 + d * DAY)
        state = json.loads(w.repo.files[LS])
        state["chains"]["8453"]["blockHash"] = "0x" + "ff" * 32
        w.repo.files[LS] = json.dumps(state)
        invalid = w.run(RUN0 + 9 * DAY)
        self.assertIsNone(invalid["apyPct"])
        self.assertIsNone(invalid["estimatedWeeklyUSD_1e18"])
        self.assertIsNone(invalid["estimatedWeeklyUSD_human"])
        self.assertTrue(invalid["stale"])
        self.assertEqual(len(json.loads(w.repo.files[LS])["history"]), 1)
        for d in range(10, 17):
            after = w.run(RUN0 + d * DAY)
        self.assertEqual(after["apySource"], "measured-7d")
        self.assertFalse(after["stale"])

    def test_lost_checkpoint_does_not_reuse_unanchored_public_history(self):
        w = World(harvests=daily_harvests(last_day=30), fundings=daily_fundings(last_day=30))
        for d in range(9):
            w.run(RUN0 + d * DAY)
        del w.repo.files[LS]
        out = w.run(RUN0 + 9 * DAY)
        self.assertIsNone(out["apyPct"])
        self.assertEqual(len(json.loads(w.repo.files[LS])["history"]), 1)

    def test_quiet_holder_scan_advances_to_its_completed_tip(self):
        from test_measured_headline import FakeRepo, FakeUpdater
        address = "0x" + "11" * 20
        repo = FakeRepo({"data/stakers.json": json.dumps({
            "checkpoint": {"last_block": 100}, "holders": [{"address": address, "balance": "5"}]})})
        updater, scanner = FakeUpdater(repo), mock.Mock()
        scanner.latest_block.return_value = 200
        scanner.erc20_transfer_logs.return_value = []
        scanner.decimals_map.return_value = {}
        scanner.w3.to_checksum_address.side_effect = lambda a: a
        scanner._call_chunk.return_value = [(True, (5).to_bytes(32, "big"))]
        scanner.total_supply.return_value = 5
        main._update_stakers(repo, updater, scanner)
        data = json.loads(repo.files["data/stakers.json"])
        self.assertEqual(data["checkpoint"]["last_block"], 200)
        main._update_stakers(repo, updater, scanner)
        self.assertEqual(scanner.erc20_transfer_logs.call_count, 1)

    def test_failed_funding_scan_keeps_its_saved_cursor(self):
        from test_measured_headline import FakeRepo, FakeUpdater
        path = "data/epochs.json"
        repo = FakeRepo({path: json.dumps({"state": {"last_block": 100}, "epochs": {}})})
        scanner = mock.Mock()
        scanner.latest_block.return_value = 200
        scanner.funded_epochs_and_tokens.side_effect = RuntimeError("missing range")
        updater = FakeUpdater(repo)
        with mock.patch.dict(os.environ, {"EPOCH_STAKING_DISTRIBUTOR": USDC}), self.assertRaises(RuntimeError):
            main._update_epochs(repo, updater, scanner)
        self.assertEqual(json.loads(repo.files[path])["state"]["last_block"], 100)
        self.assertEqual(updater.writes, [])


class ExposurePricingControls(unittest.TestCase):
    def test_zero_exposure_label_token_is_not_sent_for_a_price(self):
        ch = _chain(8453, T0, NOW, E18, [_g2(G_CL, fees={USDC: 10**6})])
        pf = mock.Mock()
        pf.fetch_batch.return_value = {USDC: {"priceUsd": 1, "source": "llama"}}
        with mock.patch.object(pe, "read_chain_position", return_value=ch), \
             mock.patch.object(pe, "token_meta", return_value=META[8453]):
            out = pe.build_live([(SimpleNamespace(chain_id=8453), None)], 1584, {8453: pf}, E18, .8, 600000)
        pf.fetch_batch.assert_called_once_with([USDC])
        self.assertTrue(out["readComplete"])

    def test_failed_position_state_read_does_not_claim_full_coverage(self):
        answers = base_answers()
        from test_position_earnings import LV
        answers.pop((LV, "tokenStates(uint256)", (1584,)))
        reader = BlockLogsReader(answers, [])
        out = pe.read_chain_position(reader, 1584, registry=pe.FACTORY_REGISTRY_BASE)
        self.assertFalse(out["gaugeListRead"])
