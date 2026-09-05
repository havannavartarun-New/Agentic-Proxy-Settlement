# One image, three roles (merchant server / Streamlit UI / buyer CLI) --
# the role is selected by the `command:`/`entrypoint:` in docker-compose.yml,
# not by building separate images, since all three share one dependency set.

FROM python:3.11-slim

# cryptography/pydantic-core ship manylinux wheels for the common platforms,
# but keep a minimal toolchain so the build still succeeds if pip has to
# compile from source on an uncommon architecture.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000 8501

# Default role: the merchant server. docker-compose.yml overrides `command`
# for the `app` (Streamlit) service and `entrypoint` for the one-off `buyer`
# and `tests` services.
CMD ["uvicorn", "merchant_server:app", "--host", "0.0.0.0", "--port", "8000"]
