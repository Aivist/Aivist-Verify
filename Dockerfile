# ==============================================================================
# Container image for the Aivist Verify confirmation-gate GitHub Action.
#
# It installs the EXISTING engine + CLI from the repo's OWN manifest
# (`pip install -e .`, whose dependencies come from backend/requirements.txt via
# pyproject.toml) — nothing is vendored or re-declared. The container's only job
# is to run the real CLI (`python run.py run --config ...`); the entrypoint is a
# thin wrapper that assembles inputs and maps the CLI's JSON result to an exit code.
#
# `openai` is added on top so the documented LLM_PROVIDER=openai seam works — this
# lets the self-test drive the engine deterministically against a local OpenAI-
# compatible stub (no live key) AND lets production users point at any OpenAI-
# compatible relay. `google-genai` (the default provider) is already in the repo
# manifest, so a real GEMINI_API_KEY works out of the box.
# ==============================================================================
FROM python:3.11-slim

# Keep Python output unbuffered so CI logs stream in real time.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /action

# Copy the repo and install the engine from its own manifest. (.dockerignore trims
# the context to what the install + runtime need.)
COPY . /action

# Install the engine from the repo manifest, then add the openai SDK for the
# documented LLM_PROVIDER=openai seam. openai is pinned to the 1.x line and the
# repo's own pins (h11 / httpcore / anyio) are HELD, so adding the SDK cannot
# perturb the versions the engine's HTTP stack (httpx -> httpcore -> h11) and
# mitmproxy are pinned to. `pip check` fails the build if anything conflicts.
RUN pip install --upgrade pip \
    && pip install -e . \
    && pip install "openai>=1.30,<2" "h11==0.14.0" "httpcore==1.0.7" "anyio>=4.3.0,<4.5.0" \
    && pip check

# The wrapper reads GitHub Action inputs (INPUT_*), loops the real CLI over each
# candidate, and exits non-zero when the gate confirms a real vuln.
ENTRYPOINT ["python", "/action/.github/action/entrypoint.py"]
