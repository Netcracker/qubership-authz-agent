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

	"authz-agent/test/parity/suite/model"
)

// eitherSourceRoute is the pip-mock path of the GENERAL PIP of
// TestRound10EitherSourceCases.
const eitherSourceRoute = "/api/v1/pip/r10-either-customer-ids"

// eitherSourceCaseID names the case and its resource type.
const eitherSourceCaseID = "either-source"

// eitherSourcePIPs declare the two sources of the condition: a TOKEN PIP over
// the reader's department claim, a string, and a GENERAL PIP answering a list
// of customer ids.
var eitherSourcePIPs = []any{
	map[string]any{"name": "subject.parityR10Department", "type": "UUID", "pipType": "TOKEN", "claim": "department", "cacheable": false},
	map[string]any{
		"name": "subject.parityR10CustomerIds", "url": "http://pip-mock:8090" + eitherSourceRoute,
		"httpMethod": "POST", "pipType": "GENERAL", "requestAttributes": map[string]string{"case": eitherSourceCaseID}, "cacheable": false,
	},
}

// What resource.customerId IN <TOKEN> OR resource.customerId IN <GENERAL>
// answers, and whether the GENERAL PIP is called once the TOKEN operand holds.
// The product policies in reach write this form with a string claim on the left
// and a GENERAL PIP answering a list of ids on the right. ro-in-either-header
// records it over two HEADER PIPs, where nothing is called; a string claim on
// the right of IN and a GENERAL PIP on the right that answered 500 beside a true
// left operand are recorded nowhere. The agent's condition parser accepts the
// condition.
//
// The reader's department claim is finance. Each request pins the GENERAL PIP,
// resets the pip-mock call log, and names the resource's customerId:
//
//   - token-holds-the-id: finance, the PIP answers [c2].
//   - general-holds-the-id: c1, the PIP answers [c1, c2]; the PIP has to be
//     called, the positive control of the route.
//   - neither-holds-the-id: c9, the PIP answers [c1].
//   - general-fails-and-token-holds-the-id: finance, the PIP answers 500.
//   - general-fails-and-token-misses-the-id: c9, the PIP answers 500; the PIP
//     has to be called.
//
// A request whose TOKEN operand holds may reach the GENERAL PIP or not, and the
// answer to general-fails-and-token-holds-the-id depends on which, so both such
// requests are recorded under -when-the-pip-was-read or -when-the-pip-was-skipped
// by the call log.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone.
func (s *ParitySuite) TestRound10EitherSourceCases() {
	ctx := context.Background()
	rt := round10ResourceType(eitherSourceCaseID)
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, eitherSourcePIPs, []any{map[string]any{
		"component":             "PARITY",
		"reason":                eitherSourceCaseID,
		"resourceType":          rt,
		"operation":             "READ",
		"roles":                 []string{"ROLE_PARITY_READER"},
		"applicableForFrontend": false,
		"condition":             "resource.customerId IN subject.parityR10Department OR resource.customerId IN subject.parityR10CustomerIds",
		"id":                    "00000000-0000-0000-0000-0000000f1040",
	}})
	s.Require().NoError(err)
	if !isAuthzAgentProfile(s.cfg.Profile) {
		s.Run("upload", func() {
			s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "isolated/"+eitherSourceCaseID, &model.PolicyLoadOutcome{Status: status})
		})
		if status < http.StatusOK || status >= http.StatusMultipleChoices {
			return
		}
	}
	ids := func(values ...string) PipStubResponse {
		return PipStubResponse{StatusCode: http.StatusOK, Body: values}
	}
	failed := PipStubResponse{StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity either-source case"}}
	for _, req := range []struct {
		name, customerID string
		response         PipStubResponse
		// mustRead is set where the GENERAL operand decides, so the PIP has to be
		// called; the other requests are classed by the call log.
		mustRead bool
	}{
		{"token-holds-the-id", "finance", ids("c2"), false},
		{"general-holds-the-id", "c1", ids("c1", "c2"), true},
		{"neither-holds-the-id", "c9", ids("c1"), true},
		{"general-fails-and-token-holds-the-id", "finance", failed, false},
		{"general-fails-and-token-misses-the-id", "c9", failed, true},
	} {
		s.Run(req.name, func() {
			s.Require().NoError(s.pipMock.PinRoute(ctx, eitherSourceRoute, req.response))
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			id, outcome := s.sendRegularRequest(rt, isolatedRequest{name: req.name, resource: map[string]any{"id": "r10-either", "customerId": req.customerID}})
			read := s.pipCalls(eitherSourceRoute)
			s.T().Logf("%s: pip-mock received %d call(s) to %s", req.name, read, eitherSourceRoute)
			subCase := "isolated/" + eitherSourceCaseID + "/" + req.name
			switch {
			case req.mustRead:
				s.Assert().Positive(read, "pip-mock calls to %s over %s", eitherSourceRoute, subCase)
			case read > 0:
				subCase += "-when-the-pip-was-read"
			default:
				subCase += "-when-the-pip-was-skipped"
			}
			s.requirePendingGolden(id, subCase, outcome)
		})
	}
}
