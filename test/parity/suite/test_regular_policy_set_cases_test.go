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
	"fmt"
	"iter"
	"maps"
	"net/http"
	"slices"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// readerTarget is the policy target every regular case grants to parity-reader.
const readerTarget = "subject.roles CONTAINS 'ROLE_PARITY_READER'"

// regularCase uploads regular policy sets, and optionally the PIPs they reference
// and simplified policies for the same resource type, then sends requests against
// them.
type regularCase struct {
	id           string
	resourceType string
	// pips and simplified policies go into isolatedCaseDomain before the sets are
	// uploaded. PIPs belong to a domain and policy sets do not, so a set that
	// reads one declares it here.
	pips       []any
	simplified []any
	// uploads run in order; each replaces the sets of its own externalID.
	uploads  []regularUpload
	requests []isolatedRequest
	// steps run in order after requests, and only when every upload was
	// accepted.
	steps []regularStep
	// cleanup is sent before the uploads and, in reverse order, when the case
	// ends, whatever its outcome; see customizationCleanup.
	cleanup []papCall
	// readsRoutes are the pip-mock routes that have to receive a call while
	// the case runs; see caseSpec.ReadsRoutes.
	readsRoutes []string
	// pipCalls is the pip-mock route whose calls over the whole case are
	// recorded as a pip-call golden; see caseSpec.PIPCalls.
	pipCalls string
	// pins are the pip-mock answers pinned when the case starts; see
	// caseSpec.Pins.
	pins map[string]PipStubResponse
}

// regularStep is one customization step of a case, as customizeStep
// describes it: call, whose status is recorded under golden, and the requests
// sent after it.
type regularStep struct {
	name     string
	call     papCall
	golden   ParityEndpointID
	requests []isolatedRequest
}

type regularUpload struct {
	externalID string
	sets       []any
}

func regularResourceType(caseID string) string {
	return "PARITY_SUITE_REG_" + strings.ToUpper(strings.ReplaceAll(caseID, "-", "_"))
}

// runRegularCases uploads the sets of each case and records the upload status and,
// once every upload was accepted, the status and the answer of every request. The
// upload status is a golden of its own, so a set the PAP refuses is a recorded
// result rather than a failed case, and the requests of a refused case are skipped
// because they would record a DENY the rules never produced.
//
// A case with PIPs or simplified policies first uploads them into the isolated
// domain and records that status as regular/<case>/declare-the-domain: the first
// of the three PUTs of [UploadIsolatedPolicies] that was not accepted, or else the
// last. When the PAP refused it, the case ends after that golden, before its
// customization cleanup, its sets, and its requests, since the sets would name PIPs
// that were never declared.
//
// When the test ends, every externalID the cases uploaded under is emptied and
// then the isolated domain is, in that order, so that no set outlives the PIP
// declarations it names. A set that does poisons the stand for every group that
// runs after it: access-control refuses every check request with 400, not only
// the ones the set's target matches.
func (s *ParitySuite) runRegularCases(cases []regularCase) {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})
	s.emptyPolicySetsOnCleanup(s.cfg, regularExternalIDs(cases)...)
	for _, tc := range cases {
		s.Run(tc.id, func() {
			s.pinRoutes(tc.pins)
			s.resetCallsFor(append(slices.Clone(tc.readsRoutes), tc.pipCalls))
			if len(tc.pips) > 0 || len(tc.simplified) > 0 {
				status, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, tc.pips, tc.simplified)
				s.Require().NoError(err)
				s.Run("declare-the-domain", func() {
					s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, "regular/"+tc.id+"/declare-the-domain", &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					return
				}
			}
			s.sendCustomizationCleanup(slices.All(tc.cleanup))
			if len(tc.cleanup) > 0 {
				s.T().Cleanup(func() { s.sendCustomizationCleanup(slices.Backward(tc.cleanup)) })
			}
			accepted := true
			for i, upload := range tc.uploads {
				status, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, upload.externalID, upload.sets)
				s.Require().NoError(err)
				s.Run(fmt.Sprintf("upload-%d", i+1), func() {
					s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, fmt.Sprintf("regular/%s/upload-%d", tc.id, i+1), &model.PolicyLoadOutcome{Status: status})
				})
				if status < http.StatusOK || status >= http.StatusMultipleChoices {
					accepted = false
				}
			}
			if !accepted {
				return
			}
			runRequests := func(requests []isolatedRequest) {
				for _, req := range requests {
					s.Run(req.name, func() {
						s.runRequest("regular/"+tc.id+"/"+req.name, tc.resourceType, req)
					})
				}
			}
			runRequests(tc.requests)
			for _, step := range tc.steps {
				status, _, err := HelperPAPCall(ctx, s.cfg, m2m, step.call)
				s.Require().NoError(err)
				s.Run(step.name, func() {
					s.requirePendingGolden(step.golden, "regular/"+tc.id+"/"+step.name, &model.PolicyLoadOutcome{Status: status})
				})
				runRequests(step.requests)
			}
			s.recordCasePIPCalls("regular/"+tc.id, tc.pipCalls)
			s.requireRoutesRead(tc.readsRoutes)
		})
	}
}

// pinRoutes pins each route of pins to its answer, in the order of the route
// names.
func (s *ParitySuite) pinRoutes(pins map[string]PipStubResponse) {
	for _, route := range slices.Sorted(maps.Keys(pins)) {
		s.Require().NoErrorf(s.pipMock.PinRoute(context.Background(), route, pins[route]), "pin %s", route)
	}
}

// resetCallsFor clears the pip-mock call log when routes names a route, so
// that requireRoutesRead and recordCasePIPCalls count the calls of one case
// alone. An empty route names none.
func (s *ParitySuite) resetCallsFor(routes []string) {
	if slices.ContainsFunc(routes, func(route string) bool { return route != "" }) {
		s.Require().NoError(s.pipMock.ResetCalls(context.Background()), "clear the pip-mock call log")
	}
}

// recordCasePIPCalls compares what route received since resetCallsFor cleared
// the log with the pip-call golden subCase. An empty route records nothing.
func (s *ParitySuite) recordCasePIPCalls(subCase, route string) {
	if route == "" {
		return
	}
	outcome := s.pipCallOutcome(route)
	s.Run("the-pip-calls", func() {
		s.requirePendingGolden(PSUITE_PIP_CALL, subCase, outcome)
	})
}

// requireRoutesRead fails the test when a route of routes received no call
// since resetCallsFor cleared the log. It records no golden. The runners call it
// after a case's requests, so a case whose upload was refused skips it.
func (s *ParitySuite) requireRoutesRead(routes []string) {
	if len(routes) == 0 {
		return
	}
	s.Run("the-pips-were-read", func() {
		calls, err := s.pipMock.GetCalls(context.Background())
		s.Require().NoError(err, "read the pip-mock call log")
		read := map[string]int{}
		for _, call := range calls {
			read[call.Path]++
		}
		for _, route := range routes {
			s.Assert().Positive(read[route], "pip-mock calls to %s", route)
		}
	})
}

// sendCustomizationCleanup sends each of calls and never fails the test. It
// logs a call that could not be sent or that the PAP answered with 5xx. A 4xx
// answer is not logged: before the upload the customization usually does not
// exist, and a refused delete of it is expected.
func (s *ParitySuite) sendCustomizationCleanup(calls iter.Seq2[int, papCall]) {
	ctx := context.Background()
	m2m := s.mustM2MToken()
	for _, call := range calls {
		status, _, err := HelperPAPCall(ctx, s.cfg, m2m, call)
		if err != nil {
			s.T().Logf("%s %s: %v", call.method, call.path, err)
		} else if status >= http.StatusInternalServerError {
			s.T().Logf("%s %s: status %d", call.method, call.path, status)
		}
	}
}

// regularExternalIDs lists the externalIDs the cases upload under, each once, in
// the order of their first upload.
func regularExternalIDs(cases []regularCase) []string {
	var ids []string
	seen := map[string]struct{}{}
	for _, tc := range cases {
		for _, upload := range tc.uploads {
			if _, dup := seen[upload.externalID]; dup {
				continue
			}
			seen[upload.externalID] = struct{}{}
			ids = append(ids, upload.externalID)
		}
	}
	return ids
}
