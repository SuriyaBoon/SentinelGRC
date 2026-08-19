import copy
import hashlib
import json
import os
import tracemalloc
from unittest import mock
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from load_soak_baseline import (
    LoadSoakProfile,
    _run_operations,
    collect_load_soak_evidence,
    validate_load_soak_evidence,
)
from scripts.collect_load_soak_evidence import OUTPUT_PATH, main


SOURCE_COMMIT = "c" * 40


class LoadSoakBaselineTests(unittest.TestCase):
    def profile(self, **overrides):
        values = {
            "unique_findings": 12,
            "replay_rounds": 1,
            "concurrency": 2,
            "duration_seconds": 0.1,
            "minimum_throughput_per_second": 0.1,
            "maximum_p95_latency_ms": 5_000,
            "maximum_peak_traced_bytes": 128 * 1024 * 1024,
        }
        values.update(overrides)
        return LoadSoakProfile(**values)

    def test_real_governance_and_outbox_path_passes_without_duplicates(self):
        envelope = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        document = validate_load_soak_evidence(envelope)["document"]
        self.assertEqual(document["decision"], "PASS")
        self.assertEqual(document["metrics"]["persisted_findings"], 12)
        self.assertEqual(document["metrics"]["expected_reassessments"], 12)
        self.assertEqual(document["metrics"]["delivered_events"], 24)
        self.assertEqual(document["metrics"]["outbox"]["pending"], 0)
        self.assertEqual(document["metrics"]["errors"], 0)
        self.assertEqual(
            len(document["metrics"]["latency_samples_ms"]),
            document["metrics"]["operations"],
        )
        self.assertTrue(all(document["gates"].values()))
        self.assertFalse(document["claim_boundary"]["current_live_gate_credit"])
        self.assertEqual(
            document["claim_boundary"]["production_decision"],
            "NO_GO_PENDING_LIVE_EVIDENCE",
        )

    def test_single_operation_is_scheduled_at_duration_boundary(self):
        profile = self.profile(
            unique_findings=1,
            replay_rounds=0,
            concurrency=1,
            duration_seconds=0.25,
        )
        core = mock.Mock()
        with mock.patch("load_soak_baseline.time.perf_counter", return_value=0.0):
            with mock.patch("load_soak_baseline.time.sleep") as sleep:
                latencies, errors = _run_operations(core, profile)

        sleep.assert_called_once_with(0.25)
        core.upsert_finding.assert_called_once()
        self.assertEqual(latencies, [0.0])
        self.assertEqual(errors, [])

    def test_threshold_breach_fails_closed_without_live_credit(self):
        envelope = collect_load_soak_evidence(
            self.profile(minimum_throughput_per_second=1_000_000), SOURCE_COMMIT
        )
        document = validate_load_soak_evidence(envelope)["document"]
        self.assertEqual(document["decision"], "NO_GO")
        self.assertFalse(document["gates"]["throughput_threshold_met"])
        self.assertFalse(document["claim_boundary"]["current_live_gate_credit"])
        self.assertFalse(document["claim_boundary"]["production_capacity_claim"])
        self.assertEqual(document["claim_boundary"]["production_decision"], "NO_GO_PENDING_LIVE_EVIDENCE")

    def test_invalid_profiles_and_source_identity_are_rejected(self):
        invalid = [
            self.profile(unique_findings=0),
            self.profile(unique_findings=1.5),
            self.profile(unique_findings=True),
            self.profile(replay_rounds=11),
            self.profile(replay_rounds=1.5),
            self.profile(concurrency=0),
            self.profile(concurrency=1.5),
            self.profile(duration_seconds=0),
            self.profile(duration_seconds=float("nan")),
            self.profile(duration_seconds=float("inf")),
            self.profile(minimum_throughput_per_second=float("nan")),
            self.profile(minimum_throughput_per_second=float("inf")),
            self.profile(maximum_p95_latency_ms=float("nan")),
            self.profile(maximum_p95_latency_ms=float("inf")),
            self.profile(maximum_peak_traced_bytes=1),
            self.profile(maximum_peak_traced_bytes=1.5),
        ]
        for profile in invalid:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                profile.validate()
        valid_profile = self.profile()
        with self.assertRaisesRegex(ValueError, "source commit"):
            collect_load_soak_evidence(valid_profile, "main")

    def test_tampering_unknown_fields_and_decision_mismatch_are_rejected(self):
        baseline = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        cases = []
        tampered = copy.deepcopy(baseline)
        tampered["document"]["source_commit_sha"] = "d" * 40
        cases.append((tampered, "checksum mismatch"))
        unknown = copy.deepcopy(baseline)
        unknown["document"]["host_name"] = "runner"
        cases.append((unknown, "fields are invalid"))
        mismatch = copy.deepcopy(baseline)
        mismatch["document"]["decision"] = "NO_GO"
        cases.append((mismatch, "decision is inconsistent"))
        for envelope, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                validate_load_soak_evidence(envelope)

    @staticmethod
    def _rehash(envelope):
        canonical = json.dumps(
            envelope["document"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        envelope["document_sha256"] = hashlib.sha256(canonical.encode("ascii")).hexdigest()
    def test_recomputed_checksum_cannot_hide_semantic_metric_forgery(self):
        forged = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        forged["document"]["metrics"]["persisted_findings"] += 1
        self._rehash(forged)

        with self.assertRaisesRegex(ValueError, "gates are inconsistent"):
            validate_load_soak_evidence(forged)

    def test_recomputed_checksum_cannot_hide_throughput_forgery(self):
        forged = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        forged["document"]["metrics"]["throughput_per_second"] += 1000
        self._rehash(forged)

        with self.assertRaisesRegex(ValueError, "throughput is inconsistent"):
            validate_load_soak_evidence(forged)

    def test_non_positive_elapsed_time_is_rejected(self):
        forged = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        forged["document"]["metrics"]["elapsed_seconds"] = 0
        self._rehash(forged)

        with self.assertRaisesRegex(ValueError, "elapsed_seconds must be positive"):
            validate_load_soak_evidence(forged)

    def test_recomputed_checksum_cannot_hide_latency_summary_forgery(self):
        forged = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        forged["document"]["metrics"]["latency_ms"] = {
            "p50": 0.0,
            "p95": 0.0,
            "p99": 0.0,
        }
        self._rehash(forged)

        with self.assertRaisesRegex(ValueError, "latency summaries are inconsistent"):
            validate_load_soak_evidence(forged)
    def test_recomputed_checksum_cannot_hide_error_latency_delivery_or_replay_forgery(self):
        cases = []
        errors = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        errors["document"]["metrics"]["error_classes"] = ["RuntimeError"]
        cases.append((errors, "error metrics are inconsistent"))
        latency = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        latency["document"]["metrics"]["latency_ms"]["p50"] = (
            latency["document"]["metrics"]["latency_ms"]["p99"] + 1
        )
        cases.append((latency, "latency order is invalid"))
        delivery = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        delivery["document"]["metrics"]["outbox"]["delivered"] -= 1
        cases.append((delivery, "delivery metrics are inconsistent"))
        replay = collect_load_soak_evidence(self.profile(), SOURCE_COMMIT)
        replay["document"]["metrics"]["actual_reassessments"] -= 1
        cases.append((replay, "gates are inconsistent"))
        for envelope, message in cases:
            with self.subTest(message=message):
                self._rehash(envelope)
                with self.assertRaisesRegex(ValueError, message):
                    validate_load_soak_evidence(envelope)

    def test_tracing_is_restored_when_collection_raises(self):
        self.assertFalse(tracemalloc.is_tracing())
        profile = self.profile()
        with mock.patch("load_soak_baseline._run_operations", side_effect=RuntimeError("stop")):
            with self.assertRaisesRegex(RuntimeError, "stop"):
                collect_load_soak_evidence(profile, SOURCE_COMMIT)
        self.assertFalse(tracemalloc.is_tracing())
    def test_hosted_runner_gate_accepts_recorded_pr127_latency(self):
        profile = self.profile(maximum_p95_latency_ms=10_000)
        metrics = {
            "operations": 24,
            "unique_findings": 12,
            "expected_reassessments": 12,
            "actual_reassessments": 12,
            "persisted_findings": 12,
            "delivered_events": 24,
            "errors": 0,
            "throughput_per_second": 3.688,
            "latency_ms": {"p50": 55.318, "p95": 2949.065, "p99": 6562.899},
            "peak_traced_bytes": 341429,
            "outbox": {"pending": 0, "dead": 0},
        }
        from load_soak_baseline import _evaluate_gates

        self.assertTrue(all(_evaluate_gates(metrics, profile).values()))

    def test_cli_writes_only_the_fixed_sanitized_output(self):
        with tempfile.TemporaryDirectory() as temp:
            previous = Path.cwd()
            try:
                os.chdir(temp)
                self.assertTrue(os.path.samefile(Path.cwd(), temp))
                stdout = StringIO()
                with redirect_stdout(stdout):
                    result = main([
                        "--source-commit", SOURCE_COMMIT,
                        "--unique-findings", "4",
                        "--concurrency", "1",
                        "--duration-seconds", "0.1",
                        "--minimum-throughput-per-second", "0.1",
                        "--maximum-p95-latency-ms", "5000",
                        "--maximum-peak-traced-bytes", str(128 * 1024 * 1024),
                    ])
                output = Path(OUTPUT_PATH)
                payload = json.loads(output.read_text(encoding="utf-8"))
            finally:
                os.chdir(previous)
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue())["output"], OUTPUT_PATH)
        self.assertFalse(payload["document"]["claim_boundary"]["current_live_gate_credit"])
        serialized = json.dumps(payload).lower()
        for prohibited in ("password", "authorization", "azurecr.io", "servicebus.windows.net"):
            self.assertNotIn(prohibited, serialized)


if __name__ == "__main__":
    unittest.main()