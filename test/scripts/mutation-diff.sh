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

# Runs mutago on the Go lines that the working tree changes since the merge
# base of HEAD and a base commit, and lists every mutant on those lines that no
# test kills. A surviving mutant is a change to that line that every test
# passes with.
#
# Usage: test/scripts/mutation-diff.sh [base]
#
# base defaults to origin/main. Because the diff starts at the merge base of
# HEAD and base, a base that moved on after the branch started adds nothing.
# Committed and uncommitted changes to tracked files count; a new file counts
# once it is committed or added with git add -N. Files under test/, _test.go
# files, and generated files are left alone.
#
# Exit status: 0 when no mutant on a changed line survives, 1 when one does,
# 2 when the run did not complete.
#
# Environment:
#   MUTAGO            command that runs mutago; default: go run of the version
#                     this script pins
#   MUTATION_TIMEOUT  seconds one run of a package's tests may take, the run
#                     before any mutation included; default 120. A mutant
#                     whose tests run longer counts as killed.
#   MUTATION_OUT      directory for the log and the summary; default
#                     test/artifacts/mutation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MUTAGO_VERSION="v2.10.40"
MUTATION_TIMEOUT="${MUTATION_TIMEOUT:-120}"
OUT_DIR="${MUTATION_OUT:-${ROOT_DIR}/test/artifacts/mutation}"

cd "${ROOT_DIR}"

# mutago parses the output of a plain git diff, so the git config settings that
# change its colors, prefixes, or paths are overridden for every git command
# the script and mutago run. The entries go after any the caller exported.
git_config_override() {
  local key="$1" value="$2"
  local index="${GIT_CONFIG_COUNT:-0}"
  export "GIT_CONFIG_KEY_${index}=${key}" "GIT_CONFIG_VALUE_${index}=${value}"
  export GIT_CONFIG_COUNT=$((index + 1))
}
git_config_override color.diff false
git_config_override diff.mnemonicPrefix false
git_config_override diff.noprefix false
git_config_override diff.srcPrefix a/
git_config_override diff.dstPrefix b/
git_config_override diff.relative false
unset GIT_EXTERNAL_DIFF

base_ref="${1:-origin/main}"
if ! git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null; then
  if [[ -z "${1:-}" ]]; then
    cat >&2 <<EOF
error: origin/main is not in this clone, so there is no commit to compare with.

The script mutates only the lines this branch changes since it left main.
Run git fetch origin main and try again, or pass the commit to compare with:
test/scripts/mutation-diff.sh <base-commit>
EOF
  else
    echo "error: ${base_ref} is not a commit in this repository; pass a branch, a tag, or a commit hash." >&2
  fi
  exit 2
fi
if ! base="$(git merge-base HEAD "${base_ref}")"; then
  echo "error: HEAD and ${base_ref} have no common ancestor; pass a commit this branch started from." >&2
  exit 2
fi
base_label="$(git rev-parse --short "${base}")"

# The reference for the first guard below: the files with at least one added
# or changed line in the diff mutago reads, the working tree against the merge
# base, parsed here from output whose format the command line fixes. A file
# whose hunks only delete lines is not one of them.
changed_files="$(git diff --no-ext-diff --no-color --src-prefix=a/ --dst-prefix=b/ --no-relative \
  --unified=0 "${base}" | awk '
  /^\+\+\+ b\// { file = substr($0, 7); next }
  /^@@/ && file != "" {
    n = split($3, r, ",")
    if ((n == 1 || r[2] + 0 > 0) && !(file in seen)) {
      seen[file] = 1
      count++
    }
  }
  END { print count + 0 }')"
sources=()
while IFS= read -r file; do
  case "${file}" in
    test/* | *_test.go | */testdata/*) continue ;;
    *) ;;
  esac
  # The generated-code marker may stand anywhere before the package clause.
  if sed -n '1,/^package /p' "${file}" | grep -q '^// Code generated .* DO NOT EDIT\.$'; then
    continue
  fi
  sources+=("${file}")
done < <(git diff --no-ext-diff --no-relative --name-only --diff-filter=AMR "${base}" -- '*.go')

if [[ "${#sources[@]}" -eq 0 ]]; then
  echo "No Go source changed between ${base_label} and the working tree outside test/, _test.go files, and generated files; nothing to mutate."
  exit 0
fi

mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
log="${OUT_DIR}/mutago.log"
summary_file="${OUT_DIR}/mutago-summary.json"
rm -f -- "${summary_file}"

# mutago writes mutago-summary.json into the directory it runs in, which is the
# root of the repository because it runs git there; the file moves to OUT_DIR
# afterwards. A baseline file that does not exist keeps a mutago-baseline.json
# in that directory from hiding any survivor.
work="$(mktemp -d)"
# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
  rm -f -- "${ROOT_DIR}/mutago-summary.json"
  rm -rf -- "${work:?}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# skip_without_test leaves out every file that has no _test.go of the same
# name, and a file's tests often live in another file of its package.
# skip_with_build_tags leaves out a file whose same-named test has a build tag.
cat >"${work}/config.yml" <<'EOF'
skip_without_test: false
skip_with_build_tags: false
exclude_dirs: []
EOF

if [[ -n "${MUTAGO:-}" ]]; then
  read -r -a mutago <<<"${MUTAGO}"
else
  mutago=(go run "github.com/quality-gates/mutago/v2/cmd/mutago@${MUTAGO_VERSION}")
fi

echo "Mutating the Go lines changed between ${base_label} and the working tree, in:"
targets=()
for file in "${sources[@]}"; do
  echo "  ${file}"
  targets+=("${ROOT_DIR}/${file}")
done

# mutago gets the changed files, not ./..., which it would walk into the
# modules under test/. With go.work in effect it reads every workspace module
# as the module path, so it runs with GOWORK=off. The numbers/* mutators shift
# integer and float literals by one and replace a non-zero float literal with
# 0.0; their survivors are mostly tuning constants and the values a function
# returns beside an error, which no test is meant to pin.
status=0
GOWORK=off "${mutago[@]}" --config="${work}/config.yml" --baseline="${work}/no-baseline.json" \
  --git-diff-lines --git-diff-base="${base}" --disable='numbers/*' \
  --exec-timeout="${MUTATION_TIMEOUT}" --fail-on-escaped \
  --verbose --quiet --logger-summary-json "${targets[@]}" >"${log}" 2>&1 || status=$?
if [[ -f mutago-summary.json ]]; then
  mv mutago-summary.json "${summary_file}"
fi

if [[ "${status}" -ne 0 && "${status}" -ne 4 ]]; then
  cat >&2 <<EOF
error: mutago exited with status ${status} before it reported every mutant; its output is in ${log}.

The last lines of the log name the cause. Status 3 is a tool error, such as
tests that already fail, or run longer than MUTATION_TIMEOUT=${MUTATION_TIMEOUT}
seconds, before any mutation; raise MUTATION_TIMEOUT when they only need more
time. Where go run cannot download mutago, set MUTAGO to a mutago binary.
EOF
  exit 2
fi

# Each mutago defect seen so far made it mutate nothing and exit 0. The run
# counts only when mutago read as many changed files as the reference above,
# and loaded every changed source file.
read_files="$(sed -n 's/^Git diff filter active against .* (\([0-9]*\) changed files)$/\1/p' "${log}")"
if [[ "${read_files}" != "${changed_files}" ]]; then
  cat >&2 <<EOF
error: mutago read ${read_files:-no} changed files from git diff, and git lists ${changed_files}.

Its result would not cover every change, so the run stops. A diff.external
driver in the git config is one known cause; run the script with a config that
sets none. The log is in ${log}.
EOF
  exit 2
fi
for file in "${sources[@]}"; do
  if ! grep -qF "Mutate \"${ROOT_DIR}/${file}\"" "${log}"; then
    cat >&2 <<EOF
error: mutago did not load ${file}, which this branch changes.

Its result would not cover that file, so the run stops. The log is in ${log}.
EOF
    exit 2
  fi
done

summary="$(cat "${summary_file}" 2>/dev/null || true)"
count() {
  local key="$1"
  local value
  value="$(sed -n "s/.*\"${key}\":\([0-9]*\).*/\1/p" <<<"${summary}")"
  echo "${value:-0}"
}
escaped="$(count escapedCount)"
errored="$(count errorCount)"
echo
echo "Mutants: $(count totalMutantsCount). Killed: $(count killedCount). Survived: ${escaped}. Skipped: $(count skippedCount). Errored: ${errored}."

if [[ "${errored}" -gt 0 ]]; then
  cat >&2 <<EOF
error: mutago could not classify ${errored} mutants: their test run ended in a way
that is neither a pass, a failure, nor a build failure.

They are neither killed nor survived, so the run stops. The log is in ${log}.
EOF
  exit 2
fi

if [[ "${escaped}" -eq 0 ]]; then
  echo "Survived on lines this branch changed: none. The log is in ${log}."
  exit 0
fi

echo "Survived on lines this branch changed: ${escaped}"
awk -v root="${ROOT_DIR}/" '
  /^ESCAPED / {
    printing = 1
    sub(/ \[checksum: [0-9a-f]+\]$/, "")
    i = index($0, root)
    if (i > 0) {
      $0 = substr($0, 1, i - 1) substr($0, i + length(root))
    }
    print ""
    print
    next
  }
  printing && /^$/ { printing = 0; next }
  printing && !/^-+$/ { print }' "${log}"
cat <<EOF

The tests pass with each change shown above, so they would also pass if that
line broke in the same way. For each survivor, add or strengthen a test through
the unit's interface, or, when the mutant changes nothing a caller can observe,
say in the pull request description why it is equivalent. Report the counts
above and the outcome of every survivor in the pull request description. The
log is in ${log}.
EOF
exit 1
