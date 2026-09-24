FROM ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc AS uv
FROM python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o requirements.txt \
    && uv pip install --system --require-hashes --no-deps --target /packages -r requirements.txt

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5 AS runtime
COPY --from=build /packages /packages
COPY loom_strands /app/loom_strands
WORKDIR /app
ENV PYTHONPATH=/packages:/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    OTEL_SDK_DISABLED=true AWS_EC2_METADATA_DISABLED=true
USER 65532:65532
ENTRYPOINT ["/usr/bin/python3", "-m", "loom_strands.main"]

FROM runtime AS fixture
COPY tests/fixture_provider.py /app/fixture_provider.py
ENTRYPOINT ["/usr/bin/python3", "/app/fixture_provider.py"]
