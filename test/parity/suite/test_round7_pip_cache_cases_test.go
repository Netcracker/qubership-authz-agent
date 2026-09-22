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
	"strings"
	"time"

	"authz-agent/test/parity/suite/model"
)

// pipCacheCaseID names the case; the resource type of its set and the ids of its
// elements derive from it.
const pipCacheCaseID = "pip-cache-cacheable-false"

// pipCachePIPRoute is the pip-mock path the GENERAL PIP of the case reads.
const pipCachePIPRoute = "/api/v1/pip/cache-probe"

// pipCachePIP declares the GENERAL PIP of the case with cacheable false and no
// cachePeriod, the declaration whose caching the case asks about.
var pipCachePIP = map[string]any{
	"name":              "subject.parityCacheProbe",
	"url":               parityPipMockBase + "/cache-probe",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"type":              "JSON",
	"jsonPath":          "$.value",
	"requestAttributes": map[string]string{"resourceType": regularResourceType(pipCacheCaseID)},
	"cacheable":         false,
}

// pipCacheRounds are the values pinned at pip-mock in turn and, for each, the
// delay before its requests are sent, counted from the moment it was pinned.
// The requests of one round are sent back to back once the delay has passed.
var pipCacheRounds = []struct {
	name  string
	value string
	after time.Duration
}{
	{"first-value", "v1", 0},
	{"second-value-after-5s", "v2", 5 * time.Second},
	{"second-value-after-70s", "v2", 70 * time.Second},
}

// Whether access-control serves a GENERAL PIP declared with cacheable false from
// a cache across requests of one subject, and for how long. permission-scope-wire
// records that the PAP echoes a declaration with cacheable false as cacheable
// true with a cachePeriod, and TestRound7FailedPIPCases is run with PIP names of
// its own because a PIP answer was seen to outlive the case that fetched it.
// Neither pins the time an answer lives.
//
// The set holds two ALLOW rules, READ when the PIP answers v1 and PROBE when it
// answers v2. pip-mock is pinned to v1 and one READ is sent, the control that
// the PIP is read and parsed. pip-mock is then pinned to v2, and READ and PROBE
// are sent 5 seconds after the change and again 70 seconds after it, one subject
// throughout. In each pair exactly one answer is true: READ when the cached v1 is
// served, PROBE when pip-mock was asked again. The pip-mock call log is read
// after every request and its count logged, so the run also shows whether a
// request that was answered from the cache reached pip-mock at all. The delays
// are the case's input, not a wait for a condition, and the 70 seconds outlive
// a cache that keeps an answer for one minute.
//
// The case lives in its own test function so that a recording run can be
// filtered to it and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestRound7PIPCacheCases() {
	if isAuthzAgentProfile(s.cfg.Profile) {
		s.T().Skip("regular policy sets are evaluated by access-control only; authz-agent loads simplified policies")
	}
	s.runPIPCacheCase(pipCacheCaseID, pipCachePIPRoute, pipCachePIP)
}

// runPIPCacheCase runs the rounds of pipCacheRounds against pip, a GENERAL PIP
// that reads route and takes its value from $.value. The set, its resource type
// and the golden names derive from caseID.
func (s *ParitySuite) runPIPCacheCase(caseID, route string, pip map[string]any) {
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		if _, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, nil, nil); err != nil {
			s.T().Logf("empty domain %s: %v", isolatedCaseDomain, err)
		}
	})

	b := regularBuilder{caseID: caseID}
	rt := regularResourceType(caseID)
	set := b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
		b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
			b.rule("read-when-v1", "operation == 'READ'", pip["name"].(string)+" == 'v1'", "ALLOW", nil),
			b.rule("probe-when-v2", "operation == 'PROBE'", pip["name"].(string)+" == 'v2'", "ALLOW", nil)),
	}, nil)

	pipStatus, err := UploadIsolatedPolicies(ctx, s.cfg, s.tokens, isolatedCaseDomain, []any{pip}, nil)
	s.Require().NoError(err)
	s.Run("declare-the-pip", func() {
		s.requirePendingGolden(PSUITE_LOAD_SIMPLIFIED_POLICIES, caseID+"/declare-the-pip", &model.PolicyLoadOutcome{Status: pipStatus})
	})
	if pipStatus < http.StatusOK || pipStatus >= http.StatusMultipleChoices {
		return
	}
	externalID := "parity-" + caseID
	s.emptyPolicySetsOnCleanup(s.cfg, externalID)
	setStatus, _, err := HelperPutPolicySets(ctx, s.cfg, m2m, externalID, []any{set})
	s.Require().NoError(err)
	s.Run("upload-the-set", func() {
		s.requirePendingGolden(PSUITE_LOAD_POLICY_SETS, caseID+"/upload-the-set", &model.PolicyLoadOutcome{Status: setStatus})
	})
	if setStatus < http.StatusOK || setStatus >= http.StatusMultipleChoices {
		return
	}

	pinned := ""
	var pinnedAt time.Time
	for _, round := range pipCacheRounds {
		if round.value != pinned {
			s.Require().NoError(s.pipMock.PinRoute(ctx, route, PipStubResponse{
				StatusCode: http.StatusOK,
				Body:       map[string]any{"value": round.value},
			}))
			pinned = round.value
			pinnedAt = time.Now()
		}
		time.Sleep(round.after - time.Since(pinnedAt))
		// The first round is the control, and one READ says whether the PIP is
		// read: a PROBE there would only record that v2 was not answered.
		operations := []string{"READ", "PROBE"}
		if round.after == 0 {
			operations = []string{"READ"}
		}
		for _, operation := range operations {
			s.Require().NoError(s.pipMock.ResetCalls(ctx))
			name := round.name + "-" + strings.ToLower(operation)
			s.Run(name, func() {
				status, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
					model.CheckAccessRequest{Operation: operation, Type: rt, Resource: map[string]any{"id": "reg-pip-cache"}},
					s.mustTokenBundle(UserProfileReader), PerCallOptions{})
				s.Require().NoError(err)
				// The call log is read before the golden is compared, since a golden
				// not yet recorded skips the rest of the subtest.
				calls, err := s.pipMock.GetCalls(ctx)
				s.Require().NoError(err)
				read := 0
				for _, call := range calls {
					if call.Path == route {
						read++
					}
				}
				s.T().Logf("pip-mock received %d call(s) to %s over %s, %s after %s was pinned", read, route, name, time.Since(pinnedAt).Round(time.Second), pinned)
				if round.after == 0 {
					s.Assert().Positive(read, "pip-mock calls to %s over %s", route, name)
				}
				s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, caseID+"/"+name,
					&model.CheckResourceOutcome{Status: status, Decision: decision})
			})
		}
	}
}
