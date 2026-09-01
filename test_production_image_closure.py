"""Production image manifest and Python import-closure policy.
Governed task: DEV-23b46174754910ce
Run with: python -m unittest test_production_image_closure -v
"""
from __future__ import annotations
import ast
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path
from typing import Any
from security_assessment import (
    _copy_spec,
    _docker_instructions,
    _read_dockerfile_text,
)
REPO_ROOT = Path(__file__).resolve().parent
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
ASSURANCE_DOCKERFILE_PATH = REPO_ROOT / "Dockerfile.assurance"
QUALIFICATION_DOCKERFILE_PATH = REPO_ROOT / "Dockerfile.qualification"
MANIFEST_PATH = REPO_ROOT / "docker_image_manifest.txt"
WHITELIST_PATH = REPO_ROOT / "config" / "runtime-dynamic-import-whitelist.json"
ASCII_AUDIT_FILES = (
    MANIFEST_PATH,
    QUALIFICATION_DOCKERFILE_PATH,
    WHITELIST_PATH,
    Path(__file__),
)
DENYLIST_PATTERNS = (
    "staging_",
    "_staging",
    "sample_",
    "_sample",
    "test_",
    "_test",
    "dev_",
    "_dev",
    "conftest",
)
REQUIRED_WHITELIST_FIELDS = {
    "importer",
    "target",
    "line",
    "reason",
    "owner",
    "expiry",
}
def _parsed_dockerfile(dockerfile_path: Path):
    """Parse one Dockerfile once through the production fail-closed parser."""
    parsed = _docker_instructions(_read_dockerfile_text(dockerfile_path))
    if parsed is None:
        raise AssertionError("Dockerfile instruction parsing failed closed")
    return parsed


def _effective_docker_instructions(dockerfile_path: Path) -> list[tuple[str, str]]:
    """Return effective instructions from the shared parsed representation."""
    return list(_parsed_dockerfile(dockerfile_path).instructions)


def _docker_copy_sources(dockerfile_path: Path) -> list[str]:
    sources: list[str] = []
    parsed = _parsed_dockerfile(dockerfile_path)
    for instruction_number, (directive, argument) in enumerate(
        parsed.instructions, start=1
    ):
        if directive != "COPY":
            continue
        spec = _copy_spec(argument, parsed.escape_character)
        if spec is None:
            raise AssertionError(
                f"Dockerfile instruction {instruction_number} (COPY) "
                "uses unsupported syntax"
            )
        sources.extend(spec.sources)
    return sources
def _copied_python_files(root: Path, dockerfile_path: Path) -> set[str]:
    copied: set[str] = set()
    for source in _docker_copy_sources(dockerfile_path):
        candidate = (root / source).resolve(strict=False)
        try:
            candidate.relative_to(root.resolve())
        except ValueError as error:
            raise AssertionError(f"Docker COPY source escapes repository: {source}") from error
        if candidate.is_file() and candidate.suffix == ".py":
            copied.add(candidate.relative_to(root).as_posix())
        elif candidate.is_dir():
            copied.update(
                path.relative_to(root).as_posix()
                for path in candidate.rglob("*.py")
            )
    return copied
def _resolve_local_import(root: Path, module_name: str) -> str | None:
    parts = module_name.split(".")
    candidate = root.joinpath(*parts).with_suffix(".py")
    if candidate.is_file():
        return candidate.relative_to(root).as_posix()
    package = root.joinpath(*parts, "__init__.py")
    if package.is_file():
        return package.relative_to(root).as_posix()
    return None
def _is_type_checking_guard(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Name) and node.id == "TYPE_CHECKING"
    ) or (
        isinstance(node, ast.Attribute) and node.attr == "TYPE_CHECKING"
    )
class _ImportVisitor(ast.NodeVisitor):
    def __init__(self, root: Path, source: Path) -> None:
        self.root = root
        self.source = source
        self.local_imports: set[str] = set()
        self.dynamic_calls: list[dict[str, Any]] = []
        self.importlib_aliases = {"importlib"}
        self.import_module_aliases: set[str] = set()
    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking_guard(node.test):
            for statement in node.orelse:
                self.visit(statement)
            return
        self.generic_visit(node)
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "importlib":
                self.importlib_aliases.add(alias.asname or alias.name)
            resolved = _resolve_local_import(self.root, alias.name)
            if resolved:
                self.local_imports.add(resolved)
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    self.import_module_aliases.add(alias.asname or alias.name)
        if node.level:
            base = self.source.parent
            for _ in range(node.level - 1):
                base = base.parent
            if node.module:
                base = base.joinpath(*node.module.split("."))
            module_candidate = base.with_suffix(".py")
            if module_candidate.is_file():
                self.local_imports.add(
                    module_candidate.relative_to(self.root).as_posix()
                )
            package_candidate = base / "__init__.py"
            if package_candidate.is_file():
                self.local_imports.add(
                    package_candidate.relative_to(self.root).as_posix()
                )
            for alias in node.names:
                child = base / f"{alias.name}.py"
                if child.is_file():
                    self.local_imports.add(child.relative_to(self.root).as_posix())
            return
        if not node.module:
            return
        resolved = _resolve_local_import(self.root, node.module)
        if resolved:
            self.local_imports.add(resolved)
        for alias in node.names:
            child = _resolve_local_import(self.root, f"{node.module}.{alias.name}")
            if child:
                self.local_imports.add(child)
    def visit_Call(self, node: ast.Call) -> None:
        call_name: str | None = None
        if isinstance(node.func, ast.Name):
            if node.func.id == "__import__" or node.func.id in self.import_module_aliases:
                call_name = node.func.id
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in self.importlib_aliases
        ):
            call_name = f"{node.func.value.id}.import_module"
        if call_name:
            target = "<computed>"
            if node.args and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, str):
                    target = node.args[0].value
            self.dynamic_calls.append(
                {"target": target, "line": node.lineno, "call": call_name}
            )
        self.generic_visit(node)
def _imports_for_file(root: Path, relative_path: str) -> _ImportVisitor:
    source = root / relative_path
    visitor = _ImportVisitor(root, source)
    visitor.visit(ast.parse(source.read_text(encoding="utf-8"), filename=str(source)))
    return visitor
def _read_manifest(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
def _read_whitelist(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="ascii"))
    if payload.get("schema_version") != "1.0" or not isinstance(payload.get("entries"), list):
        raise AssertionError("dynamic import whitelist must use schema_version 1.0")
    return payload["entries"]
class ProductionImageClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.copied = _copied_python_files(REPO_ROOT, DOCKERFILE_PATH)
        cls.whitelist = _read_whitelist(WHITELIST_PATH)
    def test_escape_directive_after_blank_line_is_ignored(self) -> None:
        parsed = _docker_instructions("\n# escape=`\nFROM scratch\n")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.escape_character, "\\")

    def test_closure_uses_shared_buildkit_command_delimiters(self) -> None:
        for separator in ("\t", "\v", "\f", "\r"):
            with self.subTest(separator=repr(separator)):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    dockerfile = Path(temporary_directory) / "Dockerfile"
                    dockerfile.write_bytes(
                        ("FROM" + separator + "scratch\n").encode("utf-8")
                    )
                    self.assertEqual(
                        _effective_docker_instructions(dockerfile),
                        [("FROM", "scratch")],
                    )

    def test_closure_preserves_continuation_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dockerfile = Path(temporary_directory) / "Dockerfile"
            dockerfile.write_text(
                "RUN echo first   \\\n  && echo second\n", encoding="utf-8"
            )
            self.assertEqual(
                _effective_docker_instructions(dockerfile),
                [("RUN", "echo first     && echo second")],
            )

    def test_closure_copy_sources_use_shared_flag_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dockerfile = Path(temporary_directory) / "Dockerfile"
            dockerfile.write_text(
                "FROM scratch\nCOPY --from=stage\v/src /dst\n",
                encoding="utf-8",
            )
            self.assertEqual(_docker_copy_sources(dockerfile), ["/src"])

    def test_declared_backtick_escape_joins_dockerfile_continuations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            dockerfile = Path(temporary_directory) / "Dockerfile"
            dockerfile.write_text(
                "# escape=`\nRUN echo first `\n  && echo second\nCOPY app.py /app/app.py\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _effective_docker_instructions(dockerfile),
                [
                    ("RUN", "echo first   && echo second"),
                    ("COPY", "app.py /app/app.py"),
                ],
            )

    def test_no_staging_test_sample_or_dev_modules_ship(self) -> None:
        offenders = sorted(
            path
            for path in self.copied
            if any(pattern in Path(path).stem for pattern in DENYLIST_PATTERNS)
        )
        self.assertEqual(offenders, [])
    def test_docker_python_copy_set_matches_positive_manifest(self) -> None:
        self.assertEqual(self.copied, _read_manifest(MANIFEST_PATH))
    def test_manifest_is_sorted_and_has_no_duplicates(self) -> None:
        entries = [
            line.strip()
            for line in MANIFEST_PATH.read_text(encoding="ascii").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(entries, sorted(set(entries)))
    def test_assurance_overlay_is_narrow_and_import_complete(self) -> None:
        overlay = _copied_python_files(REPO_ROOT, ASSURANCE_DOCKERFILE_PATH)
        self.assertEqual(
            overlay,
            {
                "live_gate_harness.py",
                "scripts/__init__.py",
                "scripts/azure_live_gate_harness.py",
                "scripts/azure_staging_validator.py",
            },
        )
        available = self.copied | overlay
        for module in (
            "live_gate_harness.py",
            "scripts/azure_live_gate_harness.py",
            "scripts/azure_staging_validator.py",
        ):
            with self.subTest(module=module):
                missing = _imports_for_file(REPO_ROOT, module).local_imports - available
                self.assertEqual(missing, set())
    def test_qualification_overlay_adds_only_hash_locked_assessment_dependencies(self) -> None:
        instructions = _effective_docker_instructions(QUALIFICATION_DOCKERFILE_PATH)
        self.assertEqual(
            instructions,
            [
                ("ARG", "RUNTIME_IMAGE=sentinelgrc:runtime-image-required"),
                ("FROM", "${RUNTIME_IMAGE}"),
                ("USER", "root"),
                (
                    "COPY",
                    "--chown=0:0 requirements-assessment-hashed.txt "
                    "/tmp/requirements-assessment-hashed.txt",
                ),
                (
                    "RUN",
                    "python -m pip install --no-cache-dir --require-hashes "
                    "--requirement /tmp/requirements-assessment-hashed.txt "
                    "    && chmod 0444 /tmp/requirements-assessment-hashed.txt",
                ),
                ("USER", "10001:10001"),
            ],
        )

    def test_local_import_closure_is_complete(self) -> None:
        missing: dict[str, list[str]] = {}
        for relative_path in sorted(self.copied):
            gap = _imports_for_file(REPO_ROOT, relative_path).local_imports - self.copied
            if gap:
                missing[relative_path] = sorted(gap)
        self.assertEqual(missing, {})
    def test_dynamic_import_calls_require_structured_declarations(self) -> None:
        declared = {
            (entry.get("importer"), entry.get("target"), entry.get("line"))
            for entry in self.whitelist
        }
        undeclared = []
        for relative_path in sorted(self.copied):
            for call in _imports_for_file(REPO_ROOT, relative_path).dynamic_calls:
                identity = (relative_path, call["target"], call["line"])
                if identity not in declared:
                    undeclared.append({"importer": relative_path, **call})
        self.assertEqual(undeclared, [])
    def test_dynamic_import_whitelist_is_current_and_targets_ship(self) -> None:
        failures = []
        for entry in self.whitelist:
            if set(entry) != REQUIRED_WHITELIST_FIELDS:
                failures.append({"entry": entry, "error": "invalid fields"})
                continue
            try:
                expiry = date.fromisoformat(str(entry["expiry"]))
            except ValueError:
                failures.append({"entry": entry, "error": "invalid expiry"})
                continue
            if expiry < date.today():
                failures.append({"entry": entry, "error": "expired"})
            if not str(entry["owner"]).strip() or not str(entry["reason"]).strip():
                failures.append({"entry": entry, "error": "owner and reason required"})
            if entry["importer"] not in self.copied:
                failures.append({"entry": entry, "error": "importer not shipped"})
            target = _resolve_local_import(REPO_ROOT, str(entry["target"]))
            if target is None or target not in self.copied:
                failures.append({"entry": entry, "error": "target not shipped"})
        self.assertEqual(failures, [])
    def test_audit_policy_files_are_ascii(self) -> None:
        non_ascii = {
            path.relative_to(REPO_ROOT).as_posix(): [byte for byte in path.read_bytes() if byte > 127]
            for path in ASCII_AUDIT_FILES
            if any(byte > 127 for byte in path.read_bytes())
        }
        self.assertEqual(non_ascii, {})
    def test_type_checking_imports_do_not_create_runtime_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "optional.py").write_text("VALUE = 1\n", encoding="ascii")
            (root / "app.py").write_text(
                "from typing import TYPE_CHECKING\n"
                "if TYPE_CHECKING:\n"
                "    import optional\n",
                encoding="ascii",
            )
            self.assertEqual(_imports_for_file(root, "app.py").local_imports, set())
    def test_importlib_calls_are_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                "import importlib as loader\n"
                "loader.import_module('plugin')\n",
                encoding="ascii",
            )
            calls = _imports_for_file(root, "app.py").dynamic_calls
            self.assertEqual(calls[0]["target"], "plugin")
if __name__ == "__main__":
    unittest.main()
