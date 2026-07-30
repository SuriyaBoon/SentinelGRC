FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp \
    SENTINEL_ENV=lab \
    SENTINEL_DATABASE_URL=sqlite:////app/runtime/governance.db \
    SENTINEL_IDENTITY_DATABASE_URL=sqlite:////app/runtime/identity.db \
    SENTINEL_EVIDENCE_DIR=/app/runtime/evidence

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && addgroup --system --gid 10001 sentinel \
    && adduser --system --uid 10001 --gid 10001 --home /nonexistent sentinel

COPY . .
RUN mkdir -p /app/runtime/evidence \
    && chown -R sentinel:sentinel /app/runtime

USER 10001:10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["gunicorn", "--bind=0.0.0.0:8080", "--workers=1", "--threads=4", "--timeout=30", "--worker-tmp-dir=/tmp", "--access-logfile=-", "--error-logfile=-", "runtime_app:application"]
