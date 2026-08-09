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
        self.assertIn("COPY --chown=0:0", assurance)
        self.assertIn("chmod 0444", assurance)
        self.assertNotIn("--chown=10001:10001", assurance)
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
        self.assertIn(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            workflow,
        )
        self.assertIn(
            "azure/login@7184910d9eb2b1c5e48f7073824a90609bb9b6d6",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            workflow,
        )
        self.assertIn(
            "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
            workflow,
        )
        self.assertNotRegex(workflow, r"(?m)^\s*uses:\s+[^\s]+@v\d+")
        self.assertEqual(workflow.count("docker buildx build --load"), 2)
        self.assertIn("--build-arg RUNTIME_IMAGE=sentinelgrc:release", workflow)
        self.assertIn("Push exact qualified layers and resolve digests", workflow)
        self.assertIn("az acr repository show", workflow)
        self.assertIn("@%s", workflow)
        self.assertNotIn("RepoDigests", workflow)
        self.assertNotIn("az containerapp", workflow)
        self.assertNotIn("az deployment", workflow)

    def test_publication_requires_unprivileged_qualification_and_exact_handoff(self):
        workflow = (
            ROOT / ".github" / "workflows" / "publish-staging-images.yml"
        ).read_text(encoding="utf-8")
        qualify = workflow.split("\n  qualify:\n", 1)[1].split(
            "\n  publish:\n", 1
        )[0]
        publish = workflow.split("\n  publish:\n", 1)[1]

        self.assertNotIn("id-token: write", qualify)
        self.assertNotIn("azure/login@", qualify)
        self.assertNotIn("az acr login", qualify)
        for gate in (
            "SENTINEL_TEST_POSTGRES_URL=postgresql://sentinel:",
            "-m unittest discover -v",
            "az bicep build --file /src/infra/azure/main.bicep",
            "curl --fail --silent --max-time 10 http://127.0.0.1:8080/ready",
            'test "$status" = "503"',
            "Unreachable PostgreSQL unexpectedly started",
            "Production startup unexpectedly passed",
        ):
            with self.subTest(gate=gate):
                self.assertIn(gate, qualify)
        self.assertIn('-p "test_*.py"', qualify)
        self.assertIn("docker image save --output qualified-images.tar", qualify)
        self.assertIn("bundle_sha256", qualify)

        self.assertIn("needs: qualify", publish)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("docker build", publish)
        self.assertIn("sha256sum --check", publish)
        self.assertIn("needs.qualify.outputs.runtime_image_id", publish)
        self.assertIn("needs.qualify.outputs.assurance_image_id", publish)
        self.assertLess(
            publish.index("Verify qualification handoff and load exact layers"),
            publish.index("Azure login with repository OIDC"),
        )

    def test_registry_digest_evidence_uses_one_run_bound_tag(self):
        workflow = (
            ROOT / ".github" / "workflows" / "publish-staging-images.yml"
        ).read_text(encoding="utf-8")
        publish = workflow.split("\n  publish:\n", 1)[1]

        self.assertIn(
            'release_tag="run-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${GITHUB_SHA}"',
            publish,
        )
        self.assertGreaterEqual(publish.count(":$release_tag"), 6)
        self.assertNotIn("sentinelgrc:${GITHUB_SHA}", publish)
        self.assertNotIn("sentinelgrc-assurance:${GITHUB_SHA}", publish)
        self.assertIn("github_run_id=%s", publish)
        self.assertIn("github_run_attempt=%s", publish)
        self.assertIn("release_tag=%s", publish)

if __name__ == "__main__":
    unittest.main()
