#!/bin/bash

# Directory holding the compiled cp1 test binaries. Defaults to the build
# output directory relative to this script's location; override with
#   BIN_DIR=/path/to/bin/cp1 ./run_tests.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_DIR="${BIN_DIR:-${REPO_ROOT}/build/bin/cp1}"

if [ ! -d "${BIN_DIR}" ]; then
    echo "error: test binary directory not found: ${BIN_DIR}" >&2
    echo "build the project first, or set BIN_DIR to the correct path" >&2
    exit 1
fi

"${BIN_DIR}"/testcase_line_easy -a; echo;
"${BIN_DIR}"/testcase_tree_easy -a; echo;
"${BIN_DIR}"/testcase_tiebreak_pathlen -a; echo;
"${BIN_DIR}"/testcase_link_failure_root -a; echo;
"${BIN_DIR}"/testcase_singleton -a; echo;
"${BIN_DIR}"/testcase_reconverge_link_failure -a; echo;
"${BIN_DIR}"/testcase_ring_even -a; echo;
