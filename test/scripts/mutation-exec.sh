#!/usr/bin/env bash

# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Runs the tests of one mutant for go-mutesting, which calls it with
# MUTATE_ORIGINAL, MUTATE_CHANGED, MUTATE_PACKAGE, and MUTATE_TIMEOUT set.
# mutation-diff.sh passes it as --exec and sets MUTATION_RESULTS and
# MUTATION_DIFFS.
#
# The mutant replaces the source file while the package tests run, and the
# file is restored on every exit. Each mutant appends one line to
# MUTATION_RESULTS: the verdict, the file, the first line the mutant changes,
# the number of lines it changes, and, for a survivor, the file in
# MUTATION_DIFFS that holds its diff.
#
# The exit status follows go-mutesting: 0 when a test fails (killed), 1 when
# every test passes (survived), 2 when the mutant does not compile (skipped).
# go test exits 1 on a build failure as well, so the build failure is read
# from its output.

set -uo pipefail

: "${MUTATION_RESULTS:?is set by test/scripts/mutation-diff.sh}"
: "${MUTATION_DIFFS:?is set by test/scripts/mutation-diff.sh}"

original="${MUTATE_ORIGINAL}"
# shellcheck disable=SC2329 # the EXIT trap calls it
restore() {
  if [[ -f "${original}.orig" ]]; then
    mv -f "${original}.orig" "${original}"
  fi
}
trap restore EXIT

mv "${original}" "${original}.orig"
cp "${MUTATE_CHANGED}" "${original}"

output="$(go test -count=1 -failfast -timeout "${MUTATE_TIMEOUT}s" "${MUTATE_PACKAGE}" 2>&1)"
status=$?

# The old-side range of the first hunk: "@@ -12,3 +12,1 @@" gives 12 and 3.
range="$(diff -U0 "${original}.orig" "${MUTATE_CHANGED}" | grep -m1 '^@@' | awk '{print substr($2, 2)}')"
line="${range%%,*}"
count=1
if [[ "${range}" == *,* ]]; then
  count="${range#*,}"
fi
if [[ "${count}" -eq 0 ]]; then
  count=1
fi

if [[ "${status}" -eq 0 ]]; then
  index="$(($(wc -l <"${MUTATION_RESULTS}" 2>/dev/null || echo 0) + 1))"
  diff_file="${MUTATION_DIFFS}/${index}.diff"
  diff -U1 "${original}.orig" "${MUTATE_CHANGED}" | tail -n +3 >"${diff_file}"
  printf 'survived\t%s\t%s\t%s\t%s\n' "${original}" "${line}" "${count}" "${diff_file}" >>"${MUTATION_RESULTS}"
  exit 1
fi
if grep -qE '\[build failed\]|\[setup failed\]' <<<"${output}"; then
  printf 'not-compiled\t%s\t%s\t%s\t-\n' "${original}" "${line}" "${count}" >>"${MUTATION_RESULTS}"
  exit 2
fi
verdict=killed
if grep -q 'panic: test timed out' <<<"${output}"; then
  verdict=timed-out
fi
printf '%s\t%s\t%s\t%s\t-\n' "${verdict}" "${original}" "${line}" "${count}" >>"${MUTATION_RESULTS}"
exit 0
