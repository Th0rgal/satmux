#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
printf '\n============================================================\n'
printf 'SATMUX RUST + DOCKER REGRESSION TESTS\n'
printf '============================================================\n'
cargo test -- --nocapture
printf '\n============================================================\n'
printf 'SATMUX DOCKER DEPLOYMENT SMOKE TEST\n'
printf '============================================================\n'
python3 tests/docker_smoke.py
printf '\n============================================================\n'
printf 'SATMUX RUST + DOCKER: ALL TESTS PASSED\n'
printf '============================================================\n'
