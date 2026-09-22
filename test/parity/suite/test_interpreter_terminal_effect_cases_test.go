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

// terminalEffectPIPRoute is the pip-mock path the GENERAL PIP of the
// terminal-effect case reads.
const terminalEffectPIPRoute = "/api/v1/pip/terminal-effect"

// terminalEffectPIP declares the GENERAL PIP whose calls the case counts.
var terminalEffectPIP = map[string]any{
	"name":              "subject.parityTerminal",
	"url":               parityPipMockBase + "/terminal-effect",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"type":              "JSON",
	"jsonPath":          "$.value",
	"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_REG_TERMINAL_EFFECT"},
	"cacheable":         false,
}

// Whether a rule whose effect decides the policy stops the rules beside it from
// being evaluated. The decision does not show it: under DENY_UNLESS_PERMIT one
// ALLOW decides whatever the other rules do. A rule that reads a GENERAL PIP
// shows it in the pip-mock call log, since the PIP is called only when its
// rule's condition is evaluated.
//
// The policy holds an ALLOW rule on resource.a and an ALLOW rule whose condition
// reads the PIP. rule-on-a-allows sends a = y, where the first rule allows on
// its own; the-pip-decides sends a = n, the control that the PIP rule is live
// and the PIP is called when it is needed. The call log is read after each
// request and logged, not compared: the order the rules are evaluated in is not
// fixed by anything the suite can see, so the count under a = y is the
// observation, whatever it is, and the count under a = n has to be positive.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterTerminalEffectCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	s.Require().NoError(s.pipMock.PinRoute(ctx, terminalEffectPIPRoute, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": "v"},
	}))

	tc := terminalEffectCases()[0]
	requests := tc.requests
	for _, req := range requests {
		s.Require().NoError(s.pipMock.ResetCalls(ctx))
		tc.requests = []isolatedRequest{req}
		s.runRegularCases([]regularCase{tc})
		s.Run(req.name+"/pip-calls", func() {
			calls, err := s.pipMock.GetCalls(ctx)
			s.Require().NoError(err)
			read := 0
			for _, call := range calls {
				if call.Path == terminalEffectPIPRoute {
					read++
				}
			}
			s.T().Logf("pip-mock received %d call(s) to %s over %s", read, terminalEffectPIPRoute, req.name)
			if req.name == "the-pip-decides" {
				s.Assert().Positive(read, "pip-mock calls to %s over %s", terminalEffectPIPRoute, req.name)
			}
		})
	}
}

// terminalEffectCases is the one case of the group, as a list for
// TestRegularCaseIDsAreUnique; the test sends its requests one at a time.
func terminalEffectCases() []regularCase {
	id := "terminal-effect-stops-the-rules-beside-it"
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return []regularCase{{
		id:           id,
		resourceType: rt,
		pips:         []any{terminalEffectPIP},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("allow-on-a", "operation == 'READ'", "resource.a == 'y'", "ALLOW", nil),
					b.rule("allow-via-pip", "operation == 'READ'", "subject.parityTerminal == 'v'", "ALLOW", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{
			{name: "rule-on-a-allows", resource: map[string]any{"id": "reg-terminal", "a": "y"}},
			{name: "the-pip-decides", resource: map[string]any{"id": "reg-terminal", "a": "n"}},
		},
	}}
}
