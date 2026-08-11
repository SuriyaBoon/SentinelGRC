"""Repository-level checks for deterministic SonarCloud analysis inputs."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SONAR_CONFIG = ROOT / "sonar-project.properties"
BINARY_SUFFIXES = frozenset(
    {
        ".db",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".pdf",
        ".png",
        ".pyc",
        ".sqlite",
        ".sqlite3",
        ".ttf",
        ".webp",
        ".woff",
        ".woff2",
        ".zip",
    }
)


def _tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        # Production images intentionally omit Git metadata. In that context,
        # validate the packaged source tree instead of weakening the encoding
        # check or making the container test depend on a repository checkout.
        return [
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and ".git" not in path.parts
            and "runtime" not in path.parts
            and "evidence-inbox" not in path.parts
            and "__pycache__" not in path.parts
        ]
    return [ROOT / name for name in result.stdout.splitlines() if name]


def _properties(path: Path) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise AssertionError(f"invalid Sonar property line: {raw_line!r}")
        properties[key.strip()] = value.strip()
    return properties


class SonarConfigurationTests(unittest.TestCase):
    def test_sonar_analysis_is_pinned_to_repository_runtime(self) -> None:
        properties = _properties(SONAR_CONFIG)
        self.assertEqual("SuriyaBoon_SentinelGRC", properties.get("sonar.projectKey"))
        self.assertEqual("suriyaboon", properties.get("sonar.organization"))
        self.assertEqual("3.12", properties.get("sonar.python.version"))
        self.assertEqual("UTF-8", properties.get("sonar.sourceEncoding"))

    def test_tracked_text_inputs_are_valid_utf8(self) -> None:
        invalid: list[str] = []
        for path in _tracked_files():
            if path.suffix.lower() in BINARY_SUFFIXES:
                continue
            try:
                path.read_bytes().decode("utf-8")
            except UnicodeDecodeError as exc:
                invalid.append(f"{path.relative_to(ROOT)}: {exc}")
        self.assertEqual([], invalid, "tracked text files must be UTF-8: " + "; ".join(invalid))


if __name__ == "__main__":
    unittest.main()
