# SBC Validator - local-first container.
#
# Runs the validation engine as a container INSIDE the customer's environment.
# It needs no network for `validate` (the only inbound channel is a signed rule
# bundle, which is baked in), so it can run fully air-gapped:
#
#   docker build -t sbc-validator .
#   docker run --rm --network none -v "$PWD/configs:/work" sbc-validator \
#       validate /work/teams.ini --ruleset rulesets/ms_direct_routing_2026-06.json
#
# --network none is the point: raw SBC configs never leave the host.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package (cryptography ships manylinux wheels; no build toolchain needed).
COPY pyproject.toml README.md ./
COPY sbc_validator ./sbc_validator
COPY rulesets ./rulesets
COPY samples ./samples
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 sbc

# Drop privileges: the engine never needs root.
USER sbc

# The local dashboard (`serve`) listens here. validate/simulate/explain/diff/fleet
# need no ports. To run the dashboard in-container, publish the port and bind 0.0.0.0:
#   docker run --rm -p 8787:8787 -v "$PWD/results:/app/results" sbc-validator \
#       serve --results /app/results --host 0.0.0.0
EXPOSE 8787

# `sbc-validator <subcommand> ...`  (validate / simulate / explain / diff / fleet / serve)
ENTRYPOINT ["sbc-validator"]
CMD ["--help"]
