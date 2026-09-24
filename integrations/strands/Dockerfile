FROM ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc AS uv
FROM python:3.14-slim-trixie@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN uv export --locked --no-dev --no-emit-project --format requirements-txt -o requirements.txt \
    && uv pip install --system --require-hashes --no-deps --target /packages -r requirements.txt

FROM cgr.dev/chainguard/python:latest@sha256:f23c2b7cd3d6b18aed6ad6e1099d79668ff62ba49078e81bb558e5a1c7581fd8 AS runtime
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
