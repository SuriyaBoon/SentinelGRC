"""Keep the organized repository discoverable without changing runtime imports."""

from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


class RepositoryLayoutTests(unittest.TestCase):
    def test_test_suites_are_grouped_and_discoverable(self):
        self.assertEqual([], list(ROOT.glob("test_*.py")))
        self.assertTrue((ROOT / "tests" / "__init__.py").is_file())
        modules = list((ROOT / "tests").glob("test_*.py"))
        self.assertGreaterEqual(len(modules), 60)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('Get-ChildItem -Path tests -File -Filter "test_*.py"', workflow)
        self.assertIn('ForEach-Object { "tests.$($_.BaseName)" }', workflow)

    def test_documentation_file_links_resolve(self):
        broken = []
        for document in [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]:
            content = document.read_text(encoding="utf-8")
            # Examples in fenced blocks are not navigation links.
            content = re.sub(r"```.*?```", "", content, flags=re.DOTALL)
            for href in re.findall(r"\]\(([^\s)]+)\)", content):
                parsed = urlsplit(href)
                if parsed.scheme or parsed.netloc or not parsed.path:
                    continue
                target = document.parent / unquote(parsed.path)
                if not target.exists():
                    broken.append(f"{document.relative_to(ROOT)}: {href}")
        self.assertEqual([], broken)

    def test_status_preserves_unverified_cloud_boundary(self):
        status = (ROOT / "docs/STATUS.md").read_text(encoding="utf-8")
        self.assertIn("NO_GO_PENDING_LIVE_EVIDENCE", status)
        self.assertIn("BLOCKED_EXTERNAL", status)
        self.assertIn("0/8 credited", status)
        self.assertTrue((ROOT / "runtime_app.py").is_file())
        self.assertTrue((ROOT / "docker_image_manifest.txt").is_file())


if __name__ == "__main__":
    unittest.main()
