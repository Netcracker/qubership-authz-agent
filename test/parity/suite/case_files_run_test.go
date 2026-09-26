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
	"strings"
	"time"
)

// runCaseFile pins the file's routes and its entitlements answer, and runs its
// isolated cases, then its regular cases, each in the file's order.
func (s *ParitySuite) runCaseFile(name string) {
	f, err := readCaseFile(name)
	s.Require().NoError(err)
	ctx := context.Background()
	for route, response := range f.Pins {
		s.Require().NoErrorf(s.pipMock.PinRoute(ctx, route, response), "pin %s for %s", route, name)
	}
	if f.Entitlements != nil {
		s.Require().NoErrorf(s.eaMock.PinEntitlementsV3ForUser(ctx, parityReaderSubjectID, *f.Entitlements), "pin the entitlements of %s", name)
	}
	var isolated []isolatedCase
	var regular []regularCase
	for _, c := range f.Cases {
		rt := f.ResourceTypePrefix + strings.ToUpper(strings.ReplaceAll(c.ID, "-", "_"))
		var pips []any
		for _, key := range c.PIPs {
			pip, ok := f.PIPs[key]
			s.Require().Truef(ok, "case %s names the PIP %q, which %s does not declare", c.ID, key, name)
			pips = append(pips, pip)
		}
		requests := caseRequests(c.Requests, rt)
		if len(c.Sets) == 0 {
			isolated = append(isolated, isolatedCase{
				id: c.ID, resourceType: rt, domain: c.Domain, operation: c.Operation, roles: c.Roles,
				condition: resourceTypeReplacer(rt).Replace(c.Condition), pips: pips, requests: requests,
				policyOmit: c.PolicyOmit, policy: c.Policy, policiesQuery: c.PoliciesQuery,
			})
			continue
		}
		b := regularBuilder{caseID: c.ID}
		ruleIDs := regularBuilder{caseID: valueOr(c.RuleIDsOf, c.ID)}
		sets := make([]any, 0, len(c.Sets))
		for _, set := range c.Sets {
			sets = append(sets, buildSet(b, ruleIDs, set, rt))
		}
		steps := make([]regularStep, 0, len(c.Customize))
		for _, st := range c.Customize {
			call, golden := customizeStepCall(c.ID, c.RuleIDsOf, st, rt)
			steps = append(steps, regularStep{name: st.Name, call: call, golden: golden, requests: caseRequests(st.Requests, rt)})
		}
		regular = append(regular, regularCase{
			id: c.ID, resourceType: rt, pips: pips,
			uploads:  []regularUpload{{externalID: "parity-" + c.ID, sets: sets}},
			requests: requests,
			steps:    steps,
			cleanup:  customizationCleanup(c.ID, c.Customize, rt),
		})
	}
	if len(isolated) > 0 {
		s.runIsolatedCases(isolated)
	}
	if len(regular) > 0 {
		// runRegularCases skips the rest of the function on the authz-agent profile,
		// which loads simplified policies only.
		s.runRegularCases(regular)
	}
}

// caseRequests turns the requests of a case whose resource type is rt into the
// form the runners send.
func caseRequests(specs []requestSpec, rt string) []isolatedRequest {
	requests := make([]isolatedRequest, 0, len(specs))
	for _, r := range specs {
		req := isolatedRequest{
			name: r.Name, operation: r.Operation, typ: r.Type, resource: withResourceType(r.Resource, rt),
			headers: r.Headers, filter: r.Filter, m2mOnly: r.Subject == "m2m", classifyBy: r.ClassifyBy,
			tenantID: r.TenantID, pipCalls: r.PIPCalls, user: r.user(),
			userClaims: r.SubjectClaims,
			userID:     r.UserID, emptyOperation: r.EmptyOperation, pipHeaders: r.PIPHeaders,
			pause: time.Duration(r.PauseMs) * time.Millisecond,
		}
		if r.Bulk != nil {
			req.bulk = bulkItems(r.Bulk, rt)
		}
		if r.BulkOperations != nil {
			req.bulkOperations = bulkItems(r.BulkOperations, rt)
		}
		requests = append(requests, req)
	}
	return requests
}

// user returns the username of a "user:" subject, and "" for any other.
func (r requestSpec) user() string {
	if name, ok := strings.CutPrefix(r.Subject, "user:"); ok {
		return name
	}
	return ""
}
