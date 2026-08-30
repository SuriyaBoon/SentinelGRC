FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    SENTINEL_ENV=lab \
    SENTINEL_DATABASE_URL=sqlite:////app/runtime/governance.db \
    SENTINEL_IDENTITY_DATABASE_URL=sqlite:////app/runtime/identity.db \
    SENTINEL_RUNTIME_ROOT=/app/runtime \
    SENTINEL_EVIDENCE_DIR=/app/runtime/evidence \
    SENTINEL_AUDIT_DIR=/app/runtime/audit-archive \
    SENTINEL_OUTBOX_DIR=/app/runtime/outbox

WORKDIR /app

COPY requirements-hashed.txt /app/requirements-hashed.txt
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 \
    && python -m pip install --no-cache-dir --require-hashes --requirement /app/requirements-hashed.txt \
    && addgroup --system --gid 10001 sentinel \
    && adduser --system --uid 10001 --gid 10001 --home /nonexistent sentinel

COPY audit_archive.py audit_delivery.py audit_log.py audit_worker.py connectors.py contract_validation.py crypto_agility.py deployment_contract.py domain_packs.py evidence_crypto.py evidence_metadata.py /app/
COPY evidence_store.py file_lock.py governance_api.py governance_core.py governance_http.py human_identity.py jml_connector.py job_queue.py migrate_json.py migration_runner.py /app/
COPY minisoar_connector.py observability.py oidc_auth.py oidc_contract.py outbox_delivery.py outbox_worker.py path_security.py persistence.py postgres_runtime_state.py production_contract.py reporting.py /app/
COPY runtime_app.py security_alert_contract.py security_event_connector.py security_pack.py sentinelgrc.py state_store.py x509_verifier.py /app/
COPY migrations/postgresql/001_canonical_governance.sql migrations/postgresql/002_runtime_delivery.sql migrations/postgresql/003_evidence_objects.sql /app/migrations/postgresql/
COPY migrations/postgresql/004_immutable_audit_exports.sql migrations/postgresql/005_service_bus_outbox.sql /app/migrations/postgresql/

RUN mkdir -p /app/runtime/evidence /app/runtime/audit-archive /app/runtime/outbox \
    && chown -R sentinel:sentinel /app/runtime

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--timeout=30", "--worker-tmp-dir=/tmp", "--access-logfile=-", "--error-logfile=-", "runtime_app:application"]
