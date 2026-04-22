#!/usr/bin/env bash
#
# Higress Rust WASM Plugin Build Script
#
# Usage: ./wasm-rust-build.sh <plugin_name>
#
# This script will:
#   1. Build the WASM binary inside Docker (handles C cross-compilation deps)
#   2. Extract plugin.wasm from the build
#   3. Build a minimal OCI image and push to registry
#

set -euo pipefail

# ────────────────────────────── Configuration ──────────────────────────────
REGISTRY="crpi-weotfxlsdxvf8tfd.cn-hangzhou.personal.cr.aliyuncs.com/higress-wasm-plugin/ai-security-guard"
TAG_PREFIX="zhengji-test"
RUST_WASM_DIR="plugins/wasm-rust"
# ──────────────────────────────────────────────────────────────────────────

# ────────────────────────────── Helper functions ──────────────────────────
log()   { echo -e "\033[1;32m[BUILD]\033[0m $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

check_command() {
    command -v "$1" &>/dev/null || error "'$1' is not installed."
}
# ──────────────────────────────────────────────────────────────────────────

# ────────────────────────────── Argument parsing ─────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <plugin_name>"
    echo "Example: $0 ai-data-masking"
    exit 1
fi

PLUGIN_NAME="$1"
PLUGIN_DIR="${RUST_WASM_DIR}/extensions/${PLUGIN_NAME}"

[[ -d "${PLUGIN_DIR}" ]] || error "Plugin directory does not exist: ${PLUGIN_DIR}"
[[ -f "${PLUGIN_DIR}/Cargo.toml" ]] || error "No Cargo.toml in ${PLUGIN_DIR}"
# ──────────────────────────────────────────────────────────────────────────

check_command docker

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
IMAGE_TAG="${TAG_PREFIX}-${TIMESTAMP}"
FULL_IMAGE="${REGISTRY}:${IMAGE_TAG}"
log "Target image: ${FULL_IMAGE}"

# ────────────────────────────── Step 1: Build WASM in Docker ─────────────
log "Step 1/3: Building WASM in Docker (using project Dockerfile)..."

docker build \
    --build-arg PLUGIN_NAME="${PLUGIN_NAME}" \
    -t "${FULL_IMAGE}" \
    "${RUST_WASM_DIR}"

log "Docker image built ✓"
# ──────────────────────────────────────────────────────────────────────────

# ────────────────────────────── Step 2: Extract WASM ─────────────────────
log "Step 2/3: Extracting plugin.wasm..."

CONTAINER_ID=$(docker create "${FULL_IMAGE}")
docker cp "${CONTAINER_ID}:plugin.wasm" "${PLUGIN_DIR}/plugin.wasm"
docker rm "${CONTAINER_ID}" >/dev/null

WASM_SIZE=$(du -h "${PLUGIN_DIR}/plugin.wasm" | cut -f1)
log "WASM extracted: ${PLUGIN_DIR}/plugin.wasm (${WASM_SIZE}) ✓"
# ──────────────────────────────────────────────────────────────────────────

# ────────────────────────────── Step 3: Push ─────────────────────────────
log "Step 3/3: Pushing image to registry..."
docker push "${FULL_IMAGE}"
log "Image pushed ✓"
# ──────────────────────────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo " Build & Push Completed!"
echo "=========================================="
echo ""
echo "  Plugin: ${PLUGIN_NAME}"
echo "  Image:  ${FULL_IMAGE}"
echo "  WASM:   ${PLUGIN_DIR}/plugin.wasm (${WASM_SIZE})"
echo ""
echo "  WasmPlugin URL:"
echo "    oci://${FULL_IMAGE}"
echo ""
echo "=========================================="
