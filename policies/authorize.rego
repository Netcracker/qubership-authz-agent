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

package authorize

import rego.v1

# Thin per-key projection of `data.authorize_internals.canonical` so that
# `data.authorize` evaluates to the canonical response object after the
# OPA-direct contract rebase (ADR-0062). All compute lives in
# `package authorize_internals` (see authorize_internals.rego) and is
# byte-identical to the pre-rebase top-level rules of this package;
# nothing here adds policy logic.
#
# No `default` rules are declared here because the defaulting branch
# lives in `authorize_internals.canonical` (today's `default result`
# branch, renamed). Pre-rebase, the admission-failure branch of `result`
# returned a single-key `{authError: ...}` object with no `rlsIgnored`
# or `results`; mirroring that requires the per-key extractions to be
# undefined when `canonical` lacks the key, so defaults must NOT live
# here. The defaulting branch in `canonical` supplies `{rlsIgnored,
# results}` only when no other branch matched, preserving pre-rebase
# byte-shape exactly.
#
# Why a sibling top-level package and not a sub-package: OPA 1.x always
# includes a sub-package in its parent's data tree (verified: even
# underscore-prefixed sub-package names like `_internals` remain visible
# under `data.authorize`). With a sub-package layout, the wire response
# of `POST /v1/data/authorize` would leak the entire internal compute
# graph (~200+ rule outputs, including `_admission_validation` and the
# raw decision tree) in the `result` envelope. A sibling package is the
# narrowest deviation from the ADR-0062 logical naming that preserves
# the wire-shape invariant. An OPA alias rule
# `data.authorize.result := data.authorize` would trigger the recursion
# check.

rlsIgnored := data.authorize_internals.canonical.rlsIgnored

results := data.authorize_internals.canonical.results

authError := data.authorize_internals.canonical.authError

# ADR-0069: echo the correlation id in the canonical response. OPA owns the id
# (data.pip.request_id): the inbound input.requestId when present, else a
# fixed-key uuid.rfc4122 stable across this evaluation (nd_builtin_cache), so the
# same id injected into every PIP/entitlements call is the one echoed here. Unlike
# the canonical-projected keys above this is always defined (every decision, incl.
# admission failure, is correlatable), so it never masks a missing-key branch.
requestId := data.pip.request_id
