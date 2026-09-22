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

package paritysuite

import (
	"context"
	"net/http"
)

// failedPIPAlgorithms are the combining algorithms the failed-PIP cases are run
// under, one case each, with the suffix that makes the case's PIP names and
// pip-mock paths its own.
var failedPIPAlgorithms = []struct{ key, name, suffix string }{
	{"deny-unless-permit", "DENY_UNLESS_PERMIT", "DenyUnlessPermit"},
	{"permit-unless-deny", "PERMIT_UNLESS_DENY", "PermitUnlessDeny"},
	{"deny-overrides", "DENY_OVERRIDES", "DenyOverrides"},
	{"permit-overrides", "PERMIT_OVERRIDES", "PermitOverrides"},
}

// failedPIPCase holds the PIP declarations and the pinned pip-mock routes of one
// failed-PIP case beside the regular case that reads them.
type failedPIPCase struct {
	regular regularCase
	// routes maps each pip-mock path the case's PIPs read to the answer pinned
	// there. The healthy route is the control: a condition that reads it allows,
	// so a case where every answer is false is not explained by pip-mock being
	// unreachable or by the declarations being dropped.
	routes map[string]PipStubResponse
}

// A rule whose condition reads a GENERAL PIP that failed, beside a rule of the
// same policy that allows, under each of the four combining algorithms.
// approve-failed-allow-beside-allow records this shape with a missing resource
// key and answers true under all four, which is what says an unresolvable value
// makes one rule inapplicable and leaves its neighbor alone. A failed PIP is the
// other way an operand fails to resolve, and whether the two are the same event
// decides whether an evaluator can drop the abort altogether.
//
// Each case reads PIPs of its own, named and routed after its algorithm, and
// runs alone with the pip-mock call log read after it. Access-control caches a
// PIP answer per subject and tenant across requests, so four cases that read
// three PIP names in turn see what the earlier cases left in the cache rather
// than what pip-mock answers now, and the-pips-were-read then fails on the case
// whose PIPs were never called. Twelve names and twelve paths give every case a
// cold cache. Every case declares all twelve, because each case's upload of the
// domain replaces its PIP declarations while the sets of the earlier cases are
// still on the stand, and a set that names a declaration the domain no longer
// holds makes access-control refuse every check request with 400.
//
// The operations split the shapes: READ an ALLOW that reads the PIP answering
// 500 beside an ALLOW, UPDATE the same with 404, DELETE a DENY that reads the
// 500 beside an ALLOW, and PROBE the rule that reads the live PIP alone.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound7FailedPIPCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	for _, tc := range failedPIPCases() {
		for path, response := range tc.routes {
			s.Require().NoError(s.pipMock.PinRoute(ctx, path, response), "pin %s", path)
		}
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
		s.runRegularCases([]regularCase{tc.regular})
		s.Run(tc.regular.id+"/the-pips-were-read", func() {
			calls, err := s.pipMock.GetCalls(ctx)
			s.Require().NoError(err)
			read := map[string]int{}
			for _, call := range calls {
				if _, pinned := tc.routes[call.Path]; pinned {
					read[call.Path]++
				}
			}
			for path := range tc.routes {
				s.Assert().Positive(read[path], "pip-mock calls to %s over the requests of %s", path, tc.regular.id)
			}
		})
	}
}

// failedPIPRegularCases is the regular part of failedPIPCases, for
// TestRegularCaseIDsAreUnique.
func failedPIPRegularCases() []regularCase {
	var cases []regularCase
	for _, tc := range failedPIPCases() {
		cases = append(cases, tc.regular)
	}
	return cases
}

func failedPIPCases() []failedPIPCase {
	var cases []failedPIPCase
	var declarations []any
	for _, algorithm := range failedPIPAlgorithms {
		id := "failed-pip-beside-allow-" + algorithm.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		broken := "subject.parityTranslatorBroken" + algorithm.suffix
		gone := "subject.parityTranslatorGone" + algorithm.suffix
		live := "subject.parityTranslatorLive" + algorithm.suffix
		// route is the pip-mock path of one of the case's PIPs; parityPipMockBase
		// is the same path prefixed with the pip-mock origin.
		route := func(kind string) string { return "/api/v1/pip/translator-" + kind + "-" + algorithm.key }
		declare := func(name, kind string, fields map[string]any) map[string]any {
			pip := map[string]any{
				"name":              name,
				"url":               parityPipMockBase + "/translator-" + kind + "-" + algorithm.key,
				"httpMethod":        "POST",
				"pipType":           "GENERAL",
				"requestAttributes": map[string]string{"resourceType": rt},
				"cacheable":         false,
			}
			for field, value := range fields {
				pip[field] = value
			}
			return pip
		}
		declarations = append(declarations,
			declare(broken, "broken", nil),
			declare(gone, "gone", nil),
			// The live one reads $.value out of the body, so its condition
			// compares a value rather than an object.
			declare(live, "live", map[string]any{"type": "JSON", "jsonPath": "$.value"}))
		cases = append(cases, failedPIPCase{
			routes: map[string]PipStubResponse{
				route("broken"): {StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity failed-pip case"}},
				route("gone"):   {StatusCode: http.StatusNotFound, Body: map[string]string{"error": "parity failed-pip case"}},
				route("live"):   {StatusCode: http.StatusOK, Body: map[string]string{"value": "v"}},
			},
			regular: regularCase{
				id:           id,
				resourceType: rt,
				uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
					b.set("set", "resourceType == '"+rt+"'", algorithm.name, []any{
						b.policy("reader", readerTarget, algorithm.name,
							b.rule("read-allow-reads-the-broken-pip", "operation == 'READ'", broken+" != 'x'", "ALLOW", nil),
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
							b.rule("update-allow-reads-the-gone-pip", "operation == 'UPDATE'", gone+" != 'x'", "ALLOW", nil),
							b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
							b.rule("delete-deny-reads-the-broken-pip", "operation == 'DELETE'", broken+" != 'x'", "DENY", nil),
							b.rule("delete-allow", "operation == 'DELETE'", "true", "ALLOW", nil),
							b.rule("probe-allow-reads-the-live-pip", "operation == 'PROBE'", live+" == 'v'", "ALLOW", nil)),
					}, nil),
				}}},
				requests: []isolatedRequest{
					{name: "failed-allow-beside-allow", operation: "READ", resource: map[string]any{"id": "tr-failed-pip"}},
					{name: "missing-allow-beside-allow", operation: "UPDATE", resource: map[string]any{"id": "tr-failed-pip"}},
					{name: "failed-deny-beside-allow", operation: "DELETE", resource: map[string]any{"id": "tr-failed-pip"}},
					{name: "live-pip-alone", operation: "PROBE", resource: map[string]any{"id": "tr-failed-pip"}},
				},
			},
		})
	}
	for i := range cases {
		cases[i].regular.pips = declarations
	}
	return cases
}
