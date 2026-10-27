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

# Mutates the Go functions that HEAD changes since its merge base with a base
# commit and lists every mutant on a changed line that no test kills. A
# surviving mutant is a change to that line that every test passes with.
#
# Usage: test/scripts/mutation-diff.sh [base]
#
# base defaults to origin/main; HEAD is compared with its merge base with
# base, so a base that moved on after the branch started adds nothing.
# Committed changes are mutated; uncommitted ones are not. Files under test/,
# _test.go files, and generated files are left alone; a renamed file counts
# as new, so all of it is mutated. The mutants run in a temporary worktree of
# HEAD, so the checkout is not modified.
#
# Exit status: 0 when no mutant on a changed line survives, 1 when one does,
# 2 when the run did not complete.
#
# Environment:
#   GO_MUTESTING      command that runs go-mutesting; default: go run of the
#                     version this script pins
#   MUTATION_TIMEOUT  seconds one run of a package's tests may take; default
#                     120. A mutant whose tests run longer counts as killed.
#   MUTATION_OUT      directory for the log, the results, and the survivors'
#                     diffs; default test/artifacts/mutation

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${ROOT_DIR}/test/scripts"
# github.com/avito-tech/go-mutesting at tag v2.3.1. The module's go.mod has no
# /v2 suffix, so go install refuses the tag; the pseudo-version names the
# same commit.
GO_MUTESTING_VERSION="v0.0.0-20251226130216-48d0401f00fb"
MUTATION_TIMEOUT="${MUTATION_TIMEOUT:-120}"
OUT_DIR="${MUTATION_OUT:-${ROOT_DIR}/test/artifacts/mutation}"

cd "${ROOT_DIR}"

# Color and an external diff driver from the user's git config would change
# the hunk headers the script reads.
git_diff() {
  git -c color.diff=false diff --no-ext-diff --no-renames "$@"
}

base_ref="${1:-origin/main}"
if ! git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null; then
  if [[ -z "${1:-}" ]]; then
    cat >&2 <<EOF
error: origin/main is not in this clone, so there is no commit to compare HEAD with.

The script mutates only the functions this branch changes since it left main.
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

if [[ -n "$(git status --porcelain -- '*.go')" ]]; then
  echo "warning: uncommitted Go changes are not mutated; commit them and run again to include them." >&2
fi

work="$(mktemp -d)"
tree="${work}/tree"
# shellcheck disable=SC2329 # the EXIT trap calls it
cleanup() {
  git -C "${ROOT_DIR}" worktree remove --force "${tree}" >/dev/null 2>&1 || true
  rm -rf -- "${work:?}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The Go sources this branch adds or modifies, with the lines it changes.
# Each line of changed-lines is "file<TAB>line<TAB>kind": kind is "changed"
# for a line HEAD adds or modifies, and "deleted" for the line after which
# HEAD deletes lines.
files=()
: >"${work}/changed-lines"
while IFS= read -r file; do
  case "${file}" in
    test/* | *_test.go | */testdata/*) continue ;;
    *) ;;
  esac
  # The generated-code marker may stand anywhere before the package clause.
  header="$(git show "HEAD:${file}" | sed -n '1,/^package /p')"
  if grep -q '^// Code generated .* DO NOT EDIT\.$' <<<"${header}"; then
    continue
  fi
  files+=("${file}")
  git_diff --unified=0 "${base}" HEAD -- "${file}" | awk -v file="${file}" '
    /^@@/ {
      n = split(substr($3, 2), r, ",")
      start = r[1] + 0
      count = (n > 1) ? r[2] + 0 : 1
      if (count == 0) {
        print file "\t" start "\tdeleted"
      }
      for (i = 0; i < count; i++) {
        print file "\t" (start + i) "\tchanged"
      }
    }' >>"${work}/changed-lines"
done < <(git_diff --name-only --diff-filter=AM "${base}" HEAD -- '*.go')

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "No Go source changed between ${base_label} and HEAD outside test/, _test.go files, and generated files; nothing to mutate."
  exit 0
fi

# The functions that hold a changed or deleted line. gofmt starts every
# top-level declaration at column 0, so a function runs from its "func" line
# to the next line that starts with "}".
: >"${work}/functions"
for file in "${files[@]}"; do
  git show "HEAD:${file}" | awk -v file="${file}" '
    NR == FNR {
      if ($1 == file) {
        touched[$2] = 1
      }
      next
    }
    /^func / {
      name = $0
      sub(/^func (\([^)]*\) )?/, "", name)
      sub(/[^A-Za-z0-9_].*$/, "", name)
      inside = 1
    }
    inside && (FNR in touched) {
      print name
    }
    /^}/ || (/^func / && /}$/) {
      inside = 0
    }' "${work}/changed-lines" - >>"${work}/functions"
done
sort -u -o "${work}/functions" "${work}/functions"

if [[ ! -s "${work}/functions" ]]; then
  echo "The Go lines changed between ${base_label} and HEAD lie outside functions; nothing to mutate."
  exit 0
fi
match="^($(paste -sd '|' "${work}/functions"))\$"

echo "Mutating the functions changed between ${base_label} and HEAD:"
paste -sd ' ' "${work}/functions" | fold -s -w 100 | sed 's/^/  /'

# mutation-exec.sh runs in the worktree, so it gets the output directory as an
# absolute path.
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"
rm -rf -- "${OUT_DIR:?}/diffs" "${OUT_DIR}/results.tsv"
mkdir "${OUT_DIR}/diffs"
: >"${OUT_DIR}/results.tsv"
log="${OUT_DIR}/go-mutesting.log"

# mutation-exec.sh replaces each mutated file in place while its tests run, so
# the run works on a worktree of HEAD rather than on the checkout.
git worktree add --detach --quiet "${tree}" HEAD

# A mutant counts as killed when a test fails or runs out of time, so the
# tests have to pass on HEAD first, within the same time limit.
packages=()
while IFS= read -r dir; do
  packages+=("./${dir}/")
done < <(for file in "${files[@]}"; do dirname "${file}"; done | sort -u)
if ! (cd "${tree}" && go test -count=1 -timeout "${MUTATION_TIMEOUT}s" "${packages[@]}") >"${OUT_DIR}/baseline.log" 2>&1; then
  cat >&2 <<EOF
error: the tests of the changed packages fail on HEAD before any mutation; the
output is in ${OUT_DIR}/baseline.log.

Every mutant would count as killed while a test fails anyway, so the run stops.
Make go test -timeout ${MUTATION_TIMEOUT}s ${packages[*]} pass, commit, and run
the script again, or raise MUTATION_TIMEOUT if the tests only need more time.
EOF
  exit 2
fi

# With either skip on, go-mutesting also skips every file that has no _test.go
# of the same name. Without silent mode it logs one line per mutant it runs,
# which the script counts against the results.
cat >"${work}/config.yml" <<'EOF'
skip_without_test: false
skip_with_build_tags: false
json_output: false
silent_mode: false
exclude_dirs: []
EOF

if [[ -n "${GO_MUTESTING:-}" ]]; then
  read -r -a go_mutesting <<<"${GO_MUTESTING}"
else
  go_mutesting=(go run "github.com/avito-tech/go-mutesting/cmd/go-mutesting@${GO_MUTESTING_VERSION}")
fi

# The numbers/* mutators shift integer and float literals by one. Their
# survivors are mostly tuning constants and the values a function returns
# beside an error, which no test is meant to pin.
if ! (
  cd "${tree}"
  MUTATION_RESULTS="${OUT_DIR}/results.tsv" MUTATION_DIFFS="${OUT_DIR}/diffs" \
    "${go_mutesting[@]}" --config="${work}/config.yml" --exec="${SCRIPT_DIR}/mutation-exec.sh" \
    --exec-timeout="${MUTATION_TIMEOUT}" --disable='numbers/*' --match="${match}" "${files[@]}"
) >"${log}" 2>&1; then
  cat >&2 <<EOF
error: go-mutesting stopped before it tested every mutant; its output is in ${log}.

The tests passed on HEAD, so the cause is go-mutesting or its download, and
the last lines of the log name it. The "undefined:" lines at the start of the
log appear on every run and are not the cause: go-mutesting type-checks each
file on its own. Where go run cannot download go-mutesting, set GO_MUTESTING
to a go-mutesting binary.
EOF
  exit 2
fi

ran="$(grep -cE ' with checksum [0-9a-f]+$' "${log}" || true)"
recorded="$(wc -l <"${OUT_DIR}/results.tsv" | tr -d ' ')"
if [[ "${ran}" -ne "${recorded}" ]]; then
  cat >&2 <<EOF
error: go-mutesting ran ${ran} mutants, and ${OUT_DIR}/results.tsv records ${recorded}.

mutation-exec.sh appends one line per mutant, so a missing line means it could
not write to that directory. The output of both is in ${log}.
EOF
  exit 2
fi

count() {
  local verdict="$1"
  awk -F '\t' -v verdict="${verdict}" '$1 == verdict { n++ } END { print n + 0 }' "${OUT_DIR}/results.tsv"
}
killed="$(count killed)"
timed_out="$(count timed-out)"
survived="$(count survived)"
not_compiled="$(count not-compiled)"
total=$((killed + timed_out + survived + not_compiled))

if [[ "${total}" -eq 0 ]]; then
  echo "go-mutesting found nothing to mutate in the changed functions."
  exit 0
fi
timeouts=""
if [[ "${timed_out}" -gt 0 ]]; then
  timeouts=" (${timed_out} by a test timeout)"
fi
echo
echo "Mutants: ${total}. Killed: $((killed + timed_out))${timeouts}. Survived: ${survived}. Did not compile: ${not_compiled}."

# A survivor counts as on a changed line when any line in any hunk of its diff
# is one, and it is named by the first such line, or by its first hunk.
awk -F '\t' '
  NR == FNR {
    if ($3 == "changed") {
      changed[$1 "\t" $2] = 1
    }
    next
  }
  $1 == "survived" {
    hunks = split($3, ranges, ",")
    on = ""
    for (h = 1; h <= hunks && on == ""; h++) {
      split(ranges[h], r, "+")
      for (i = 0; i < r[2]; i++) {
        if (($2 "\t" (r[1] + i)) in changed) {
          on = r[1] + i
          break
        }
      }
    }
    split(ranges[1], first, "+")
    print (on != "" ? "on" : "off") "\t" $2 ":" (on != "" ? on : first[1]) "\t" $4
  }' "${work}/changed-lines" "${OUT_DIR}/results.tsv" >"${work}/survivors"

on_changed="$(awk -F '\t' '$1 == "on" { n++ } END { print n + 0 }' "${work}/survivors")"
off_changed=$((survived - on_changed))

if [[ "${off_changed}" -gt 0 ]]; then
  echo
  echo "Survived in the changed functions, on lines this branch did not change: ${off_changed}"
  awk -F '\t' '$1 == "off" { print "  " $2 "  " $3 }' "${work}/survivors"
fi

if [[ "${on_changed}" -eq 0 ]]; then
  echo
  echo "Survived on lines this branch changed: none. The log and the results are in ${OUT_DIR}."
  exit 0
fi

echo
echo "Survived on lines this branch changed: ${on_changed}"
while IFS=$'\t' read -r where location diff_file; do
  if [[ "${where}" == on ]]; then
    echo
    echo "${location}"
    cat "${diff_file}"
  fi
done <"${work}/survivors"
cat <<EOF

The tests pass with each change shown above, so they would also pass if that
line broke in the same way. For each survivor, add or strengthen a test through
the unit's interface, or, when the mutant changes nothing a caller can observe,
say in the pull request description why it is equivalent. Report the counts
above and the outcome of every survivor in the pull request description. The
log and the results are in ${OUT_DIR}.
EOF
exit 1
