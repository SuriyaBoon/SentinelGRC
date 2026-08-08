import inspect
import json
import tempfile
import unittest
from pathlib import Path

from job_queue import SQLiteJobQueue
from scripts import agent_keys, ingestion_api, pipeline, pipeline_worker
from scripts.path_policy import load_json_under_root, require_exact_output, resolve_under_root
from state_store import DEFAULT_STATE_DB, SQLiteStateStore


class RuntimePathPolicyTests(unittest.TestCase):
    def test_valid_relative_and_absolute_inputs_under_root_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(resolve_under_root("nested/input.json", root), (root / "nested/input.json").resolve())
            self.assertEqual(resolve_under_root(root / "state.db", root), (root / "state.db").resolve())

    def test_relative_and_absolute_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir()
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root("../outside.json", root)
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root(Path(directory) / "outside.json", root)

    def test_symlink_escape_is_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root, outside = Path(directory) / "runtime", Path(directory) / "outside"
            root.mkdir(); outside.mkdir()
            link = root / "escape"
            try: link.symlink_to(outside, target_is_directory=True)
            except OSError as error: self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root(link / "evidence.json", root)

    def test_safe_json_read_stays_inside_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / "input.json"
            source.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
            self.assertEqual(load_json_under_root(source, root), {"status": "ok"})

    def test_output_argument_must_match_constant_allowlist_value(self):
        require_exact_output("runtime/report.json", "runtime/report.json", purpose="report path")
        require_exact_output("runtime\\report.json", "runtime/report.json", purpose="report path")
        with self.assertRaisesRegex(ValueError, "must be exactly"):
            require_exact_output("../report.json", "runtime/report.json", purpose="report path")

    def test_state_database_default_is_shared_across_components(self):
        self.assertEqual(SQLiteStateStore.__init__.__defaults__, (DEFAULT_STATE_DB,))
        self.assertEqual(SQLiteJobQueue.__init__.__defaults__, (DEFAULT_STATE_DB,))
        self.assertEqual(agent_keys.AgentKeyRegistry.__init__.__defaults__, (DEFAULT_STATE_DB,))
        self.assertEqual(pipeline.PIPELINE_PATHS["state_db"], DEFAULT_STATE_DB)
        self.assertIn("default=DEFAULT_STATE_DB", inspect.getsource(agent_keys.main))
        self.assertIn("default=DEFAULT_STATE_DB", inspect.getsource(ingestion_api.main))
        self.assertIn("default=DEFAULT_STATE_DB", inspect.getsource(pipeline_worker.add_worker_arguments))

    def test_empty_and_null_byte_input_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "non-empty"): resolve_under_root("", directory)
            with self.assertRaisesRegex(ValueError, "null byte"): resolve_under_root("bad\x00name", directory)


if __name__ == "__main__": unittest.main()
