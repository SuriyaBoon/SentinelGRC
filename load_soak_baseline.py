"""Bounded hermetic load and soak baseline for the governance/outbox path."""

from __future__ import annotations

import hashlib
import json
import math
import re
import tempfile
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from governance_core import ActorContext, GovernanceCore
from outbox_delivery import GovernanceOutboxQueue, MemoryOutboxPublisher, OutboxWorker


SCHEMA_VERSION = "sentinel.hermetic_load_soak.v1"
PRODUCTION_DECISION = "NO_GO_PENDING_LIVE_EVIDENCE"
SOURCE_SHA = re.compile(r"[0-9a-f]{40}")
ERROR_CLASS = re.compile(r"[A-Za-z_]\w{0,127}", re.ASCII)


@dataclass(frozen=True)
class LoadSoakProfile:
    unique_findings: int = 80
    replay_rounds: int = 1
    concurrency: int = 4
    duration_seconds: float = 1.0
    minimum_throughput_per_second: float = 1.0
    maximum_p95_latency_ms: float = 2_000.0
    maximum_peak_traced_bytes: int = 128 * 1024 * 1024

    def validate(self) -> None:
        _bounded_integer(
            self.unique_findings, "unique_findings must be between 1 and 10000", 1, 10_000
        )
        _bounded_integer(
            self.replay_rounds, "replay_rounds must be between 0 and 10", 0, 10
        )
        _bounded_integer(
            self.concurrency, "concurrency must be between 1 and 16", 1, 16
        )
        _bounded_number(
            self.duration_seconds,
            "duration_seconds must be between 0.1 and 300",
            0.1,
            300,
        )
        _positive_number(
            self.minimum_throughput_per_second, "minimum throughput must be positive"
        )
        _positive_number(
            self.maximum_p95_latency_ms, "maximum p95 latency must be positive"
        )
        _bounded_integer(
            self.maximum_peak_traced_bytes,
            "maximum peak traced bytes must be between 1 MiB and 2 GiB",
            1_048_576,
            2_147_483_648,
        )


def _bounded_integer(value: Any, message: str, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(message)


def _finite_number(value: Any, message: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(message)
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(message)
    return number


def _bounded_number(value: Any, message: str, minimum: float, maximum: float) -> None:
    number = _finite_number(value, message)
    if not minimum <= number <= maximum:
        raise ValueError(message)


def _positive_number(value: Any, message: str) -> None:
    if _finite_number(value, message) <= 0:
        raise ValueError(message)


def _percentile(values: list[float], percentile: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil((percentile / 100) * len(ordered)) - 1)
    return round(ordered[index], 3)


def _canonical(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _work_items(profile: LoadSoakProfile) -> list[int]:
    identities = list(range(profile.unique_findings))
    return identities + identities * profile.replay_rounds


def _run_operations(core: GovernanceCore, profile: LoadSoakProfile) -> tuple[list[float], list[str]]:
    actor = ActorContext("load-soak-analyst", "analyst", "hermetic_test")
    items = _work_items(profile)
    started = time.perf_counter()
    lock = threading.Lock()
    latencies: list[float] = []
    errors: list[str] = []

    def execute(position_and_identity: tuple[int, int]) -> None:
        position, identity = position_and_identity
        target = started + (profile.duration_seconds * (position + 1) / len(items))
        remaining = target - time.perf_counter()
        if remaining > 0:
            time.sleep(remaining)
        operation_started = time.perf_counter()
        try:
            core.upsert_finding(
                f"LOAD-{identity:08d}",
                "CTRL-LOAD-SOAK",
                f"ASSET-{identity:08d}",
                "Hermetic load and soak finding",
                "load-soak-owner",
                "medium",
                actor,
            )
        except Exception as error:  # evidence records only the exception class
            with lock:
                errors.append(type(error).__name__)
        finally:
            with lock:
                latencies.append((time.perf_counter() - operation_started) * 1000)

    with ThreadPoolExecutor(max_workers=profile.concurrency) as executor:
        list(executor.map(execute, enumerate(items)))
    return latencies, errors


def _drain_outbox(core: GovernanceCore, maximum: int) -> tuple[int, dict[str, int | float]]:
    queue = GovernanceOutboxQueue(core.database)
    publisher = MemoryOutboxPublisher()
    worker = OutboxWorker(queue, publisher, "hermetic-load-worker")
    delivered = 0
    for _ in range(maximum + 1):
        outcome = worker.run_once()
        if outcome == "empty":
            break
        if outcome == "delivered":
            delivered += 1
    return delivered, queue.metrics()


def collect_load_soak_evidence(profile: LoadSoakProfile, source_commit: str) -> dict[str, Any]:
    profile.validate()
    if SOURCE_SHA.fullmatch(source_commit) is None:
        raise ValueError("source commit SHA is invalid")
    operation_count = profile.unique_findings * (profile.replay_rounds + 1)
    with tempfile.TemporaryDirectory(prefix="sentinel-load-soak-") as temporary:
        core = GovernanceCore(str(Path(temporary) / "governance.db"))
        tracing_started_here = not tracemalloc.is_tracing()
        if tracing_started_here:
            tracemalloc.start()
        try:
            cpu_started = time.process_time()
            wall_started = time.perf_counter()
            latencies, errors = _run_operations(core, profile)
            delivered, outbox = _drain_outbox(core, operation_count)
            elapsed = max(time.perf_counter() - wall_started, 0.000001)
            cpu_seconds = time.process_time() - cpu_started
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            if tracing_started_here:
                tracemalloc.stop()
        finding_count = core.export_summary()["total"]
        elapsed_seconds = max(round(elapsed, 6), 0.000001)
        latency_samples = [round(value, 3) for value in latencies]
        reassessed_count = sum(
            event["event_type"] == "finding_reassessed"
            for identity in range(profile.unique_findings)
            for event in core.list_events(f"LOAD-{identity:08d}")
        )

    metrics = {
        "operations": operation_count,
        "unique_findings": profile.unique_findings,
        "expected_reassessments": profile.unique_findings * profile.replay_rounds,
        "actual_reassessments": reassessed_count,
        "persisted_findings": finding_count,
        "delivered_events": delivered,
        "errors": len(errors),
        "error_classes": sorted(set(errors)),
        "elapsed_seconds": elapsed_seconds,
        "throughput_per_second": round(operation_count / elapsed_seconds, 3),
        "latency_samples_ms": latency_samples,
        "latency_ms": {
            "p50": _percentile(latency_samples, 50),
            "p95": _percentile(latency_samples, 95),
            "p99": _percentile(latency_samples, 99),
        },
        "cpu_seconds": round(cpu_seconds, 3),
        "peak_traced_bytes": peak_bytes,
        "outbox": outbox,
    }
    gates = _evaluate_gates(metrics, profile)
    document = {
        "schema_version": SCHEMA_VERSION,
        "mode": "hermetic_ci",
        "source_commit_sha": source_commit,
        "profile": asdict(profile),
        "metrics": metrics,
        "gates": gates,
        "decision": "PASS" if all(gates.values()) else "NO_GO",
        "claim_boundary": {
            "azure_mutation_performed": False,
            "current_live_gate_credit": False,
            "production_decision": PRODUCTION_DECISION,
            "production_capacity_claim": False,
        },
    }
    return {"document": document, "document_sha256": hashlib.sha256(_canonical(document).encode("ascii")).hexdigest()}


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{field} must be a finite non-negative number")
    return float(value)


def _evaluate_gates(metrics: dict[str, Any], profile: LoadSoakProfile) -> dict[str, bool]:
    operation_count = profile.unique_findings * (profile.replay_rounds + 1)
    outbox = metrics["outbox"]
    return {
        "no_operation_errors": metrics["errors"] == 0,
        "finding_cardinality_exact": metrics["persisted_findings"] == profile.unique_findings,
        "replay_did_not_duplicate_findings": metrics["actual_reassessments"] == profile.unique_findings * profile.replay_rounds,
        "all_events_delivered_once": metrics["delivered_events"] == operation_count,
        "outbox_drained": outbox["pending"] == 0 and outbox["dead"] == 0,
        "throughput_threshold_met": metrics["throughput_per_second"] >= profile.minimum_throughput_per_second,
        "p95_latency_threshold_met": metrics["latency_ms"]["p95"] <= profile.maximum_p95_latency_ms,
        "memory_threshold_met": metrics["peak_traced_bytes"] <= profile.maximum_peak_traced_bytes,
    }


def _validated_profile(value: Any) -> LoadSoakProfile:
    expected = set(LoadSoakProfile.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("load and soak profile fields are invalid")
    try:
        profile = LoadSoakProfile(**value)
        profile.validate()
    except TypeError as error:
        raise ValueError("load and soak profile types are invalid") from error
    return profile


def _validate_metric_shape(metrics: Any) -> None:
    expected = {
        "operations", "unique_findings", "expected_reassessments",
        "actual_reassessments", "persisted_findings", "delivered_events",
        "errors", "error_classes", "elapsed_seconds", "throughput_per_second",
        "latency_samples_ms", "latency_ms", "cpu_seconds",
        "peak_traced_bytes", "outbox",
    }
    if not isinstance(metrics, dict) or set(metrics) != expected:
        raise ValueError("load and soak metric fields are invalid")


def _validate_integer_metrics(metrics: dict[str, Any]) -> None:
    names = (
        "operations", "unique_findings", "expected_reassessments",
        "actual_reassessments", "persisted_findings", "delivered_events",
        "errors", "peak_traced_bytes",
    )
    if any(
        isinstance(metrics[name], bool)
        or not isinstance(metrics[name], int)
        or metrics[name] < 0
        for name in names
    ):
        raise ValueError("load and soak integer metrics are invalid")


def _validate_cardinality(metrics: dict[str, Any], profile: LoadSoakProfile) -> None:
    expected_operations = profile.unique_findings * (profile.replay_rounds + 1)
    if (
        metrics["operations"] != expected_operations
        or metrics["unique_findings"] != profile.unique_findings
        or metrics["expected_reassessments"]
        != profile.unique_findings * profile.replay_rounds
    ):
        raise ValueError("load and soak metric cardinality is inconsistent")


def _validate_error_metrics(metrics: dict[str, Any]) -> None:
    classes = metrics["error_classes"]
    if not isinstance(classes, list) or any(
        not isinstance(name, str) or ERROR_CLASS.fullmatch(name) is None
        for name in classes
    ):
        raise ValueError("load and soak error classes are invalid")
    if (metrics["errors"] == 0) != (len(classes) == 0):
        raise ValueError("load and soak error metrics are inconsistent")


def _validate_latency(metrics: dict[str, Any]) -> None:
    latency = metrics["latency_ms"]
    if not isinstance(latency, dict) or set(latency) != {"p50", "p95", "p99"}:
        raise ValueError("load and soak latency metrics are invalid")
    for name in ("p50", "p95", "p99"):
        _number(latency[name], f"latency {name}")
    if not latency["p50"] <= latency["p95"] <= latency["p99"]:
        raise ValueError("load and soak latency order is invalid")
    samples = metrics["latency_samples_ms"]
    if not isinstance(samples, list) or len(samples) != metrics["operations"]:
        raise ValueError("load and soak latency samples are invalid")
    for sample in samples:
        _number(sample, "latency sample")
    expected = {
        "p50": _percentile(samples, 50),
        "p95": _percentile(samples, 95),
        "p99": _percentile(samples, 99),
    }
    if latency != expected:
        raise ValueError("load and soak latency summaries are inconsistent")


def _validate_outbox(metrics: dict[str, Any]) -> None:
    outbox = metrics["outbox"]
    expected = {"delivered", "pending", "dead", "retrying", "oldest_pending_age_seconds"}
    if not isinstance(outbox, dict) or set(outbox) != expected:
        raise ValueError("load and soak outbox metrics are invalid")
    for name in ("delivered", "pending", "dead", "retrying"):
        if isinstance(outbox[name], bool) or not isinstance(outbox[name], int) or outbox[name] < 0:
            raise ValueError("load and soak outbox counts are invalid")
    _number(outbox["oldest_pending_age_seconds"], "oldest pending age")
    if outbox["delivered"] != metrics["delivered_events"]:
        raise ValueError("load and soak delivery metrics are inconsistent")


def _validate_metrics(metrics: Any, profile: LoadSoakProfile) -> None:
    _validate_metric_shape(metrics)
    _validate_integer_metrics(metrics)
    _validate_cardinality(metrics, profile)
    elapsed = _number(metrics["elapsed_seconds"], "elapsed_seconds")
    if elapsed <= 0:
        raise ValueError("elapsed_seconds must be positive")
    throughput = _number(metrics["throughput_per_second"], "throughput_per_second")
    expected_throughput = round(metrics["operations"] / elapsed, 3)
    if throughput != expected_throughput:
        raise ValueError("load and soak throughput is inconsistent")
    _number(metrics["cpu_seconds"], "cpu_seconds")
    _validate_error_metrics(metrics)
    _validate_latency(metrics)
    _validate_outbox(metrics)

def validate_load_soak_evidence(envelope: dict[str, Any]) -> dict[str, Any]:
    if set(envelope) != {"document", "document_sha256"} or not isinstance(envelope["document"], dict):
        raise ValueError("load and soak evidence envelope is invalid")
    document = envelope["document"]
    expected = {"schema_version", "mode", "source_commit_sha", "profile", "metrics", "gates", "decision", "claim_boundary"}
    if set(document) != expected or document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("load and soak evidence fields are invalid")
    if document["mode"] != "hermetic_ci" or SOURCE_SHA.fullmatch(document["source_commit_sha"]) is None:
        raise ValueError("load and soak evidence identity is invalid")
    profile = _validated_profile(document["profile"])
    _validate_metrics(document["metrics"], profile)
    gates = document["gates"]
    expected_gates = _evaluate_gates(document["metrics"], profile)
    if not isinstance(gates, dict) or set(gates) != set(expected_gates) or any(type(value) is not bool for value in gates.values()):
        raise ValueError("load and soak gate fields are invalid")
    if gates != expected_gates:
        raise ValueError("load and soak gates are inconsistent with metrics")
    boundary = document["claim_boundary"]
    if boundary != {
        "azure_mutation_performed": False,
        "current_live_gate_credit": False,
        "production_decision": PRODUCTION_DECISION,
        "production_capacity_claim": False,
    }:
        raise ValueError("load and soak claim boundary is invalid")
    if document["decision"] not in {"PASS", "NO_GO"} or (document["decision"] == "PASS") != all(gates.values()):
        raise ValueError("load and soak decision is inconsistent")
    digest = hashlib.sha256(_canonical(document).encode("ascii")).hexdigest()
    if envelope["document_sha256"] != digest:
        raise ValueError("load and soak evidence checksum mismatch")
    return envelope