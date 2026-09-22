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
	"encoding/json"
	"net/http"
)

// A rule whose condition reads a GENERAL PIP that answers a JSON number or a
// JSON boolean, beside a rule of the same policy that allows. No golden records
// such a value in a condition: the limits of t8a and t8b are pinned as strings.
// failed-pip-beside-allow-*
// records that a PIP answering 500 beside an allowing rule refuses the whole
// answer. The agent's converter accepts every set here.
//
// The shape is failed-pip-beside-allow-*'s, under the same two algorithms,
// where a permit is not terminal and every rule is evaluated whatever order the
// stand takes them in. READ is an ALLOW reading the number beside an ALLOW,
// UPDATE the same with the boolean, DELETE a DENY reading the number beside an
// ALLOW, and PROBE the rule that reads a PIP answering a string, alone: the
// control that the declarations and pip-mock work. Each PIP reads $.value out
// of the body at a path named after its algorithm, and the-pips-were-read
// counts each path.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound9NonStringPIPValueCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	s.runFailedPIPCases(nonStringPIPValueCases())
}

// nonStringPIPValueRegularCases is the regular part of nonStringPIPValueCases, for
// TestRegularCaseIDsAreUnique.
func nonStringPIPValueRegularCases() []regularCase {
	var cases []regularCase
	for _, tc := range nonStringPIPValueCases() {
		cases = append(cases, tc.regular)
	}
	return cases
}

func nonStringPIPValueCases() []failedPIPCase {
	var cases []failedPIPCase
	var declarations []any
	for _, algorithm := range failedPIPAlgorithms {
		id := "non-string-pip-beside-allow-" + algorithm.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		name := func(kind string) string { return "subject.parityR9" + kind + algorithm.suffix }
		route := func(kind string) string { return "/api/v1/pip/r9-value-" + kind + "-" + algorithm.key }
		declare := func(kind string) map[string]any {
			return map[string]any{
				"name":              name(kind),
				"url":               parityPipMockBase + "/r9-value-" + kind + "-" + algorithm.key,
				"httpMethod":        "POST",
				"pipType":           "GENERAL",
				"type":              "JSON",
				"jsonPath":          "$.value",
				"requestAttributes": map[string]string{"resourceType": rt},
				"cacheable":         false,
			}
		}
		declarations = append(declarations, declare("Number"), declare("Boolean"), declare("String"))
		ok := func(value any) PipStubResponse {
			return PipStubResponse{StatusCode: http.StatusOK, Body: map[string]any{"value": value}}
		}
		cases = append(cases, failedPIPCase{
			routes: map[string]PipStubResponse{
				route("Number"):  ok(json.Number("1000")),
				route("Boolean"): ok(true),
				route("String"):  ok("v"),
			},
			regular: regularCase{
				id:           id,
				resourceType: rt,
				uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
					b.set("set", "resourceType == '"+rt+"'", algorithm.name, []any{
						b.policy("reader", readerTarget, algorithm.name,
							b.rule("read-allow-reads-the-number", "operation == 'READ'", name("Number")+" != 'x'", "ALLOW", nil),
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
							b.rule("update-allow-reads-the-boolean", "operation == 'UPDATE'", name("Boolean")+" != 'x'", "ALLOW", nil),
							b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
							b.rule("delete-deny-reads-the-number", "operation == 'DELETE'", name("Number")+" != 'x'", "DENY", nil),
							b.rule("delete-allow", "operation == 'DELETE'", "true", "ALLOW", nil),
							b.rule("probe-allow-reads-the-string", "operation == 'PROBE'", name("String")+" == 'v'", "ALLOW", nil)),
					}, nil),
				}}},
				requests: []isolatedRequest{
					{name: "number-allow-beside-allow", operation: "READ", resource: map[string]any{"id": "r9-pip-value"}},
					{name: "boolean-allow-beside-allow", operation: "UPDATE", resource: map[string]any{"id": "r9-pip-value"}},
					{name: "number-deny-beside-allow", operation: "DELETE", resource: map[string]any{"id": "r9-pip-value"}},
					{name: "string-pip-alone", operation: "PROBE", resource: map[string]any{"id": "r9-pip-value"}},
				},
			},
		})
	}
	for i := range cases {
		cases[i].regular.pips = declarations
	}
	return cases
}

// pipCacheCacheableCaseID names the cacheable case; the resource type of its set
// and the ids of its elements derive from it.
const pipCacheCacheableCaseID = "pip-cache-cacheable-true"

// pipCacheCacheableRoute is the pip-mock path pipCacheCacheablePIP reads.
const pipCacheCacheableRoute = "/api/v1/pip/r9-cache-cacheable"

// pipCacheCacheablePIP is pipCachePIP with cacheable true and no cachePeriod,
// under a name and a path of its own.
var pipCacheCacheablePIP = map[string]any{
	"name":              "subject.parityR9CacheCacheable",
	"url":               parityPipMockBase + "/r9-cache-cacheable",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"type":              "JSON",
	"jsonPath":          "$.value",
	"requestAttributes": map[string]string{"resourceType": regularResourceType(pipCacheCacheableCaseID)},
	"cacheable":         true,
}

// How long access-control serves a GENERAL PIP declared cacheable with no
// cachePeriod from its cache. pip-cache-cacheable-false records one call per
// request for a declaration that is not cacheable; a cacheable one is not
// recorded, and a cache that keeps an answer across requests is the one thing
// an evaluator with no cache would differ in only by its call count.
//
// The rounds are pip-cache-cacheable-false's: v1 and one READ, the control that
// the PIP is read; then v2, and READ and PROBE 5 seconds and again 70 seconds
// after the change. In each pair exactly one answer is true: READ while the
// cached v1 is served, PROBE once pip-mock was asked again. The call count of
// every request is logged.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestRound9PIPCacheCacheableCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	s.runPIPCacheCase(pipCacheCacheableCaseID, pipCacheCacheableRoute, pipCacheCacheablePIP)
}
