#!/usr/bin/env bash
# =============================================================================
# setup.sh — TinyCC Lab Environment Setup
# Runs INSIDE the Docker container as 'labuser'.
#
# What this script does:
#   1. Clones TinyCC into ~/trustlab/tinycc-clean  (never modified)
#   2. Clones TinyCC into ~/trustlab/tinycc-infected (your experiment copy)
#   3. Builds TinyCC from source in both directories
#   4. Compiles login.c with the infected copy of TinyCC
#   5. Verifies the login binary behaves correctly
# =============================================================================

set -euo pipefail   # exit on error, unset vars are errors, pipe failures count

# --------------------------------------------------------------------------
# Colour helpers (safe even if the terminal doesn't support them)
# --------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
fail()    { echo -e "${RED}[FAIL]${RESET}  $*" >&2; exit 1; }
header()  { echo -e "\n${BOLD}=== $* ===${RESET}"; }

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
TRUSTLAB="${HOME}/trustlab"
CLEAN="${TRUSTLAB}/tinycc-clean"
INFECTED="${TRUSTLAB}/tinycc-infected"
WORKSPACE="${TRUSTLAB}/workspace"

# Official TinyCC repository (hosted on Savannah / repo.or.cz)
TINYCC_REPO="https://repo.or.cz/tinycc.git"

# =============================================================================
# STEP 1 — Verify directory structure
# =============================================================================
header "Step 1: Verify directory structure"
mkdir -p "${WORKSPACE}"
info "trustlab root : ${TRUSTLAB}"
info "clean copy    : ${CLEAN}"
info "infected copy : ${INFECTED}"
info "workspace     : ${WORKSPACE}"
success "Directory structure ready."

# =============================================================================
# STEP 2 — Clone TinyCC (clean, unmodified reference copy)
# =============================================================================
header "Step 2: Clone TinyCC → tinycc-clean  (reference copy, DO NOT MODIFY)"

if [ -d "${CLEAN}/.git" ]; then
    info "tinycc-clean already cloned, skipping."
else
    info "Cloning from ${TINYCC_REPO} ..."
    git clone --depth=1 "${TINYCC_REPO}" "${CLEAN}"
    success "tinycc-clean cloned."
fi

# =============================================================================
# STEP 3 — Clone TinyCC (infected, experiment copy)
# =============================================================================
header "Step 3: Clone TinyCC → tinycc-infected  (your experiment copy)"

if [ -d "${INFECTED}/.git" ]; then
    info "tinycc-infected already cloned, skipping."
else
    info "Cloning from ${TINYCC_REPO} ..."
    git clone --depth=1 "${TINYCC_REPO}" "${INFECTED}"
    success "tinycc-infected cloned."
fi

# =============================================================================
# STEP 4 — Build TinyCC from source in BOTH directories
#
# TinyCC build process:
#   ./configure   — detects host compiler, sets install prefix, etc.
#   make          — compiles tcc and its runtime library (libtcc1.a)
#
# After a successful build the 'tcc' binary lives directly in the source
# directory (not in a separate bin/ subfolder).
# =============================================================================
build_tinycc() {
    local DIR="$1"
    local LABEL="$2"

    header "Building TinyCC in ${LABEL} (${DIR})"
    cd "${DIR}"

    if [ -f "${DIR}/tcc" ]; then
        info "tcc binary already present in ${LABEL}, skipping build."
        return
    fi

    info "Running ./configure ..."
    ./configure

    info "Running make (this may take a minute) ..."
    # Limit parallel jobs to avoid OOM in constrained Docker environments
    make -j"$(nproc)"

    if [ -f "${DIR}/tcc" ]; then
        success "TinyCC built successfully in ${LABEL}."
    else
        fail "Build failed — 'tcc' binary not found in ${DIR}"
    fi

    cd - > /dev/null
}

build_tinycc "${CLEAN}"    "tinycc-clean"
build_tinycc "${INFECTED}" "tinycc-infected"

# =============================================================================
# STEP 5 — Compile login.c using the INFECTED copy of TinyCC
#
# Important flags explained:
#   -B <dir>   Tell TCC where its own runtime files live (libtcc1.a, etc.).
#              When running TCC from its build directory (before 'make install'),
#              you must pass -B <tcc-build-dir> so it can find those files.
#              Without -B, TCC looks in /usr/local/lib/tcc/ which does not yet
#              exist.
# =============================================================================
header "Step 5: Compile login.c with tinycc-infected"

LOGIN_SRC="${WORKSPACE}/login.c"
LOGIN_BIN="${WORKSPACE}/login"

if [ ! -f "${LOGIN_SRC}" ]; then
    fail "login.c not found at ${LOGIN_SRC}. Was it copied into the image?"
fi

info "Compiling ${LOGIN_SRC} → ${LOGIN_BIN}"
"${INFECTED}/tcc" -B "${INFECTED}" "${LOGIN_SRC}" -o "${LOGIN_BIN}"
success "Compiled successfully: ${LOGIN_BIN}"

# =============================================================================
# STEP 6 — Verify login binary behaviour
#
# Expected results:
#   ./login root       → exit 0  (success)
#   ./login alice      → exit 1  (failure)
#   ./login (no arg)   → exit 1  (usage error)
# =============================================================================
header "Step 6: Verify login binary"

run_test() {
    local DESC="$1"
    local EXPECTED_EXIT="$2"
    shift 2
    local OUTPUT ACTUAL_EXIT=0
    OUTPUT=$("${LOGIN_BIN}" "$@" 2>&1) || ACTUAL_EXIT=$?

    if [ "${ACTUAL_EXIT}" -eq "${EXPECTED_EXIT}" ]; then
        success "TEST PASS  | ${DESC}"
        echo         "           | output      : ${OUTPUT}"
        echo         "           | exit code   : ${ACTUAL_EXIT} (expected ${EXPECTED_EXIT})"
    else
        fail "TEST FAIL  | ${DESC}"$'\n'"           | output    : ${OUTPUT}"$'\n'"           | exit code : ${ACTUAL_EXIT} (expected ${EXPECTED_EXIT})"
    fi
}

run_test "root login    → exit 0" 0 "root"
run_test "alice login   → exit 1" 1 "alice"
run_test "no argument   → exit 1" 1

# =============================================================================
# SUMMARY
# =============================================================================
header "Setup Complete"
echo
echo "  Directory layout:"
echo "  ${TRUSTLAB}/"
echo "  ├── tinycc-clean/      ← unmodified reference (DO NOT TOUCH)"
echo "  ├── tinycc-infected/   ← your experiment copy"
echo "  └── workspace/"
echo "      └── login.c / login"
echo
echo "  To compile a C file with TinyCC manually:"
echo "  ${INFECTED}/tcc -B ${INFECTED} <source.c> -o <output>"
echo
echo "  To run login tests:"
echo "  ${LOGIN_BIN} root    # expect exit 0"
echo "  ${LOGIN_BIN} alice   # expect exit 1"
echo
success "All steps completed successfully."
