import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class SupplyChainPolicyTests(unittest.TestCase):
    def test_runtime_dependencies_are_hash_locked_in_build_and_ci(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        lock = (ROOT / "requirements-hashed.txt").read_text(encoding="utf-8")
        self.assertIn("--require-hashes --requirement /app/requirements-hashed.txt", dockerfile)
        self.assertEqual(workflow.count("--require-hashes --requirement requirements-hashed.txt"), 2)
        self.assertNotIn("requirements.txt", dockerfile)
        self.assertIn("--hash=sha256:", lock)
        self.assertNotRegex(lock, r"(?m)^[a-zA-Z0-9_.-]+\s*(?:>=|~=|>|<)")

    def test_container_context_uses_explicit_runtime_allowlist(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        assurance = (ROOT / "Dockerfile.assurance").read_text(encoding="utf-8")
        self.assertNotIn("COPY . .", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^COPY\s+[^\n]*\*")
        self.assertNotRegex(dockerfile, r"(?m)^COPY\s+(?:tests?|docs|\.git|\.github)(?:/|\s)")
        for required in (
            "runtime_app.py",
            "outbox_worker.py",
            "migrations/postgresql/005_service_bus_outbox.sql",
        ):
            with self.subTest(required=required):
                self.assertIn(required, dockerfile)
        self.assertNotIn("staging_assurance.py", dockerfile)
        self.assertNotIn("scripts/azure_staging_validator.py", dockerfile)
        self.assertIn("ARG RUNTIME_IMAGE", assurance)
        self.assertIn("FROM ${RUNTIME_IMAGE}", assurance)
        self.assertIn("scripts/azure_staging_validator.py", assurance)
        self.assertNotIn("COPY . .", assurance)

    def test_runtime_tmpfs_is_private_and_owned_by_the_non_root_user(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "--tmpfs /app/runtime:rw,noexec,nosuid,uid=10001,gid=10001,mode=0700,size=64m",
            workflow,
        )
        self.assertNotIn("destination=/app/runtime,tmpfs-size=", workflow)

    def test_staging_image_publication_is_manual_digest_only_and_does_not_deploy(self):
        workflow = (
            ROOT / ".github" / "workflows" / "publish-staging-images.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("environment: staging-image-publish", workflow)
        self.assertEqual(workflow.count("docker buildx build --load"), 2)
        self.assertIn("--build-arg RUNTIME_IMAGE=sentinelgrc:release", workflow)
        self.assertIn("Push the exact tested image layers", workflow)
        self.assertIn("az acr repository show", workflow)
        self.assertIn("@%s", workflow)
        self.assertNotIn("RepoDigests", workflow)
        self.assertNotIn("az containerapp", workflow)
        self.assertNotIn("az deployment", workflow)

if __name__ == "__main__":
    unittest.main()
