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

# Globbed rather than listed, so a new testcase*.cpp is picked up without
# having to be added here too.
status=0
for test in "${BIN_DIR}"/testcase_*; do
    [ -x "${test}" ] || continue
    if ! "${test}" -a; then
        status=1
        echo "FAILED: $(basename "${test}")" >&2
    fi
    echo
done

exit "${status}"
