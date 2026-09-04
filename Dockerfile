FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

RUN useradd --create-home --uid 10001 dribik
USER dribik
WORKDIR /workspace

ENTRYPOINT ["dribik"]
CMD ["--help"]
