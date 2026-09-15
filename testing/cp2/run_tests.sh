#!/bin/bash

# Directory holding the compiled cp2 test binaries. Defaults to the build
# output directory relative to this script's location; override with
#   BIN_DIR=/path/to/bin/cp2 ./run_tests.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${BIN_DIR:-${REPO_ROOT}/build/bin/cp2}"

if [ ! -d "${BIN_DIR}" ]; then
    echo "error: test binary directory not found: ${BIN_DIR}" >&2
    echo "build the project first, or set BIN_DIR to the correct path" >&2
    exit 1
fi

"${BIN_DIR}"/testcase_sp_uniform_ring -a; echo;
"${BIN_DIR}"/testcase_ping -a; echo;
"${BIN_DIR}"/testcase_sp_weighted -a; echo;
"${BIN_DIR}"/testcase_sp_tiebreak -a; echo;
"${BIN_DIR}"/testcase_sp_zero_cost -a; echo;
