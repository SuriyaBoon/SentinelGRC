import json
import tempfile
import unittest
from pathlib import Path

from scripts.path_policy import (
    load_json_under_root,
    resolve_under_root,
    write_text_under_root,
)


class RuntimePathPolicyTests(unittest.TestCase):
    def test_valid_relative_and_absolute_paths_under_root_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = resolve_under_root("nested/report.json", root)
            absolute = resolve_under_root(root / "state.db", root)
            self.assertEqual(relative, (root / "nested" / "report.json").resolve())
            self.assertEqual(absolute, (root / "state.db").resolve())

    def test_relative_and_absolute_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            root.mkdir()
            outside = Path(directory) / "outside.json"
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root("../outside.json", root)
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root(outside, root)

    def test_symlink_escape_is_rejected_when_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runtime"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            link = root / "escape"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symlinks are unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "must remain under"):
                resolve_under_root(link / "evidence.json", root)

    def test_safe_json_read_and_text_write_stay_inside_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.json"
            source.write_text(json.dumps({"status": "ok"}), encoding="utf-8")
            self.assertEqual(load_json_under_root(source, root), {"status": "ok"})
            destination = write_text_under_root(
                "nested/output.json", root, '{"written": true}\n'
            )
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"written": true}\n')

    def test_empty_and_null_byte_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "non-empty"):
                resolve_under_root("", directory)
            with self.assertRaisesRegex(ValueError, "null byte"):
                resolve_under_root("bad\x00name", directory)


if __name__ == "__main__":
    unittest.main()