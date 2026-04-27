#!/usr/bin/env bash
# =============================================================================
# run.sh — Build the Docker image and launch the TinyCC lab container
#
# Run this script from macOS (from the directory containing the Dockerfile).
#
# Usage:
#   ./run.sh          — build image (if needed) and drop into interactive shell
#   ./run.sh setup    — build image, run setup.sh automatically, then exit
# =============================================================================

set -euo pipefail

IMAGE_NAME="tinycc-lab"
CONTAINER_NAME="tinycc-lab-container"

# --------------------------------------------------------------------------
# Resolve the directory this script lives in so it works from any cwd
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo " TinyCC Cybersecurity Lab — Docker Runner"
echo "=========================================="
echo "  Image    : ${IMAGE_NAME}"
echo "  Source   : ${SCRIPT_DIR}"
echo

# --------------------------------------------------------------------------
# Step 1: Build the Docker image
#   --no-cache is omitted intentionally so repeated runs are faster.
#   Add --no-cache if you need a completely fresh build.
# --------------------------------------------------------------------------
echo "[1/2] Building Docker image '${IMAGE_NAME}' ..."
docker build \
    --tag "${IMAGE_NAME}" \
    --file "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"
echo "[1/2] Image built successfully."
echo

# --------------------------------------------------------------------------
# Step 2: Run the container
#
#   -it                  : interactive terminal
#   --rm                 : remove container automatically on exit (keeps things clean)
#   --name               : give the container a friendly name
#   --hostname tinycc-lab: makes the shell prompt recognisable
#
# Two modes:
#   default  → interactive shell (you run setup.sh manually)
#   'setup'  → run setup.sh non-interactively and print all output
# --------------------------------------------------------------------------
if [ "${1:-}" = "setup" ]; then
    echo "[2/2] Running setup.sh inside container (non-interactive) ..."
    docker run \
        --rm \
        --name "${CONTAINER_NAME}" \
        --hostname "tinycc-lab" \
        "${IMAGE_NAME}" \
        bash /home/labuser/setup.sh
else
    echo "[2/2] Launching interactive shell inside container ..."
    echo "      Tip: run './setup.sh' once you are inside."
    echo
    docker run \
        -it \
        --rm \
        --name "${CONTAINER_NAME}" \
        --hostname "tinycc-lab" \
        "${IMAGE_NAME}" \
        bash
fi
