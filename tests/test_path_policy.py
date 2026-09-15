import inspect
import json
import tempfile
import unittest
from pathlib import Path

from job_queue import SQLiteJobQueue
from scripts import agent_keys, ingestion_api, pipeline, pipeline_worker
from scripts.path_policy import (
    load_json_under_root,
    require_exact_output,
    resolve_under_root,
    validate_evidence_id,
    write_text_under_root,
)
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

    def test_write_text_is_confined_to_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir()
            written = write_text_under_root("report.json", root, "{}\n")
            self.assertEqual(written.read_text(encoding="utf-8"), "{}\n")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                write_text_under_root("../escaped.json", root, "forbidden")
            self.assertFalse((Path(directory) / "escaped.json").exists())

    def test_write_text_rejects_symlink_escape_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root, outside = Path(directory) / "runtime", Path(directory) / "outside"
            root.mkdir(); outside.mkdir()
            link = root / "escape"
            try: link.symlink_to(outside, target_is_directory=True)
            except OSError as error: self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                write_text_under_root(link / "report.json", root, "forbidden")

    def test_write_text_rejects_non_allowlisted_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "not an allowed runtime output"):
                write_text_under_root("arbitrary.json", root, "forbidden")

    def test_worker_output_requires_fixed_family_and_validated_evidence_id(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            written = write_text_under_root("reports/evidence-001.json", root, "{}\n")
            self.assertEqual(written.resolve().relative_to(root.resolve()).as_posix(), "reports/evidence-001.json")
            runtime_written = write_text_under_root(
                "runtime/reports/evidence-002.json", root, "{}\n"
            )
            self.assertEqual(
                runtime_written.resolve().relative_to(root.resolve()).as_posix(),
                "runtime/reports/evidence-002.json",
            )
            for unsafe in (
                "reports/../escape.json",
                "other/evidence-001.json",
                "reports/bad id.json",
                "runtime/other/evidence-001.json",
                "runtime/reports/../escape.json",
            ):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    write_text_under_root(unsafe, root, "forbidden")

    def test_evidence_identity_is_portable_and_shared_by_output_policy(self):
        for valid in ("evidence-001", "host.example_2", "A9"):
            with self.subTest(valid=valid):
                self.assertEqual(validate_evidence_id(valid), valid)
        for invalid in ("bad id", "../escape", "evidence/child", "évidence", "CON", "lpt9.log", "x" * 128):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_evidence_id(invalid)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "reserved filesystem name"):
                write_text_under_root("reports/CON.json", directory, "forbidden")

    def test_pipeline_parameter_boundary_is_bounded(self):
        self.assertLessEqual(len(inspect.signature(pipeline.run_pipeline).parameters), 13)

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
