// Copyright 2024-2026 Netcracker Technology Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package runtimetest

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// d2FrozenCheckFamily is the shared justification for the check-family
// negative-path (400/401) responses the suite does not exercise. The 400/401
// contract is identical across the check/resource, check/resource/bulk* and
// check/filter variants; the v1 check/resource, check/resource/bulk and
// check/filter negative-path steps are the representative coverage. Per-variant
// negative tests are NOT added because the non-canonical check surface is
// D2-frozen by the ADR-0062 canonical-parity task (integration scenarios that
// do not target /access/v1/authorize must not be modified). A future task that
// lifts D2 (or adds per-variant negative steps) removes these entries.
const d2FrozenCheckFamily = "check-family 400/401 is identical across variants; covered by the v1 check/resource + bulk + filter representatives. Per-variant negative tests are D2-frozen (non-canonical surface) under the ADR-0062 task."

// previewBulkOperationsUnexercised justifies the fully-unexercised /preview
// bulk/operations routes. These are real Envoy routes backed by
// check_resource_bulk_operations.lua, but the suite exercises only the /access
// sibling endpoints (route_security.{v1,v2}_bulk_operations.implemented), never
// the /preview variants — so all three declared statuses (200/400/401) are
// unexercised. Adding a /preview step is a D2-frozen non-canonical test edit
// under the ADR-0062 task.
const previewBulkOperationsUnexercised = "preview bulk/operations is a real Envoy route, but the suite exercises only the /access sibling, not the /preview variant. Adding a /preview test is frozen as a non-canonical edit under ADR-0062 (D2)."

// healthUnavailableUnexercised justifies GET /health 503. The agent returns
// it only while OPA is not ready or the strict-mode JWKS bootstrap has not
// succeeded for every IdP. The harness runs the suite against a healthy agent
// and does not start a degraded one, so the status is unexercised here; the
// transitions are covered by the unit tests in
// components/pap-client/internal/policyadmin/health_test.go.
const healthUnavailableUnexercised = "GET /health 503 needs an agent whose OPA is not ready or whose strict-mode JWKS bootstrap failed; the harness runs the suite against a healthy agent. Covered by the policyadmin unit tests."

// reachabilityWhitelist lists spec-declared responses that a full Compose suite
// run does not exercise and that this task may not add a test for, each with the
// reason it stays unexercised (ADR-0064). The lint's pass-2 flags any entry that
// is no longer declared in the spec, or that has become exercised, so the list
// cannot silently rot into a rubber stamp that re-hides drift.
var reachabilityWhitelist = map[responseTriple]string{
	// /access check-family variants whose happy-200 is exercised but whose
	// 400/401 negative paths are not (representative coverage lives on v1).
	{Method: "POST", Path: "/access/v1/check/resource/bulk/operations", Status: 400}: d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v1/check/resource/bulk/operations", Status: 401}: d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/resource", Status: 400}:                 d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/resource", Status: 401}:                 d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/resource/bulk/operations", Status: 400}: d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/resource/bulk/operations", Status: 401}: d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/filter", Status: 400}:                   d2FrozenCheckFamily,
	{Method: "POST", Path: "/access/v2/check/filter", Status: 401}:                   d2FrozenCheckFamily,

	// /preview bulk/operations: fully unexercised (200/400/401) — the suite
	// only hits the /access siblings.
	{Method: "POST", Path: "/preview/v1/check/resource/bulk/operations", Status: 200}: previewBulkOperationsUnexercised,
	{Method: "POST", Path: "/preview/v1/check/resource/bulk/operations", Status: 400}: previewBulkOperationsUnexercised,
	{Method: "POST", Path: "/preview/v1/check/resource/bulk/operations", Status: 401}: previewBulkOperationsUnexercised,
	{Method: "POST", Path: "/preview/v2/check/resource/bulk/operations", Status: 200}: previewBulkOperationsUnexercised,
	{Method: "POST", Path: "/preview/v2/check/resource/bulk/operations", Status: 400}: previewBulkOperationsUnexercised,
	{Method: "POST", Path: "/preview/v2/check/resource/bulk/operations", Status: 401}: previewBulkOperationsUnexercised,

	// /health 503: needs a degraded agent the harness does not run.
	{Method: "GET", Path: "/health", Status: 503}: healthUnavailableUnexercised,
}

// TestZZZResponseReachabilityCoverage is the ADR-0064 response-reachability
// lint. It runs last in the suite (lexicographically after
// TestZZDecisionLogsCatalogCoverage) so the conformance hook's exercised-set is
// fully populated by every prior step. It closes the reverse direction the
// forward-only validator cannot: every (path, method, status) response declared
// in the OpenAPI document must have been exercised by at least one runtime
// exchange or be explicitly whitelisted with a reason. The orphan
// /access/v1/authorize '401' that motivated ADR-0064 fails this lint (authorize
// only ever returns 200, and 401 is not whitelisted).
//
// Gated to the full-suite invocation (FULL_RUNTIME_SUITE=true): a filtered run
// leaves the exercised-set incomplete and would false-flag — the same
// constraint TestZZDecisionLogsCatalogCoverage lives under.
func (s *RuntimeSuite) TestZZZResponseReachabilityCoverage() {
	if os.Getenv("FULL_RUNTIME_SUITE") != "true" {
		s.T().Skip("response-reachability lint requires the full suite (FULL_RUNTIME_SUITE=true)")
	}

	doc, _, err := LoadSpec()
	s.Require().NoError(err, "load openapi spec for reachability lint")

	exercised := exercisedResponseSet()

	// Pass 1: every declared response is exercised or whitelisted.
	declared := map[responseTriple]bool{}
	var orphans []string
	for _, path := range doc.Paths.InMatchingOrder() {
		item := doc.Paths.Find(path)
		for method, op := range item.Operations() {
			if op.Responses == nil {
				continue
			}
			for code := range op.Responses.Map() {
				status, convErr := strconv.Atoi(code)
				if convErr != nil {
					// The spec declares only concrete numeric statuses today.
					// A non-numeric key (default / 5XX pattern) has no single
					// reachable status — surface it so it is handled explicitly.
					orphans = append(orphans, fmt.Sprintf("%s %s [%s] — non-numeric status key; declare explicit numeric responses", method, path, code))
					continue
				}
				triple := responseTriple{Method: method, Path: path, Status: status}
				declared[triple] = true
				if exercised[triple] {
					continue
				}
				if _, ok := reachabilityWhitelist[triple]; ok {
					continue
				}
				orphans = append(orphans, fmt.Sprintf("%s %s %d — declared but never exercised at runtime and not whitelisted", method, path, status))
			}
		}
	}

	// Pass 2: the whitelist cannot rot. Every entry must still be declared and
	// still be genuinely unexercised; otherwise it is stale and must be removed.
	var stale []string
	for triple := range reachabilityWhitelist {
		switch {
		case !declared[triple]:
			stale = append(stale, fmt.Sprintf("%s %s %d — whitelisted but no longer declared in the spec; remove the whitelist entry", triple.Method, triple.Path, triple.Status))
		case exercised[triple]:
			stale = append(stale, fmt.Sprintf("%s %s %d — whitelisted but now exercised by the suite; remove the whitelist entry", triple.Method, triple.Path, triple.Status))
		}
	}

	sort.Strings(orphans)
	sort.Strings(stale)
	s.Assert().Empty(orphans, "orphan spec responses (declared but unreachable):\n%s", strings.Join(orphans, "\n"))
	s.Assert().Empty(stale, "stale response-reachability whitelist entries:\n%s", strings.Join(stale, "\n"))
}
