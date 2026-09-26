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
)

// runCaseFile pins the file's routes and runs its isolated cases, then its
// regular cases, each in the file's order.
func (s *ParitySuite) runCaseFile(name string) {
	f, err := readCaseFile(name)
	s.Require().NoError(err)
	ctx := context.Background()
	for route, response := range f.Pins {
		s.Require().NoErrorf(s.pipMock.PinRoute(ctx, route, response), "pin %s for %s", route, name)
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
		requests := make([]isolatedRequest, 0, len(c.Requests))
		for _, r := range c.Requests {
			requests = append(requests, isolatedRequest{
				name: r.Name, operation: r.Operation, typ: r.Type, resource: withResourceType(r.Resource, rt),
				headers: r.Headers, filter: r.Filter, m2mOnly: r.Subject == "m2m", classifyBy: r.ClassifyBy,
				tenantID: r.TenantID, pipCalls: r.PIPCalls, user: r.user(),
				userClaims: r.SubjectClaims,
			})
		}
		if len(c.Sets) == 0 {
			isolated = append(isolated, isolatedCase{
				id: c.ID, resourceType: rt, domain: c.Domain, operation: c.Operation, roles: c.Roles,
				condition: resourceTypeReplacer(rt).Replace(c.Condition), pips: pips, requests: requests,
			})
			continue
		}
		b := regularBuilder{caseID: c.ID}
		ruleIDs := regularBuilder{caseID: valueOr(c.RuleIDsOf, c.ID)}
		sets := make([]any, 0, len(c.Sets))
		for _, set := range c.Sets {
			sets = append(sets, buildSet(b, ruleIDs, set, rt))
		}
		regular = append(regular, regularCase{
			id: c.ID, resourceType: rt, pips: pips,
			uploads:  []regularUpload{{externalID: "parity-" + c.ID, sets: sets}},
			requests: requests,
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

// buildSet turns set into the wire form regularBuilder writes, with the
// resource type placeholders in every target and condition replaced. Rule ids
// come from ruleIDs, and every other id from b.
func buildSet(b, ruleIDs regularBuilder, set setSpec, rt string) map[string]any {
	sub := resourceTypeReplacer(rt).Replace
	policies := make([]any, 0, len(set.Policies))
	for _, p := range set.Policies {
		rules := make([]any, 0, len(p.Rules))
		for _, r := range p.Rules {
			rule := b.rule(r.Key, sub(r.Target), sub(r.Condition), r.Effect, nil)
			rule["ruleId"] = ruleIDs.id("rule/" + r.Key)
			for field, predicate := range r.Predicates {
				rule[field] = predicate
			}
			rules = append(rules, rule)
		}
		policies = append(policies, b.policy(p.Key, sub(p.Target), p.Algorithm, rules...))
	}
	var nested []any
	for _, n := range set.Sets {
		nested = append(nested, buildSet(b, ruleIDs, n, rt))
	}
	out := b.set(set.Key, sub(set.Target), set.Algorithm, policies, nested)
	if set.Status != "" {
		out["status"] = set.Status
	}
	if set.Iterate != nil {
		out["iterate"] = map[string]any{"foreach": set.Iterate.Foreach, "combiningAlgorithm": set.Iterate.Algorithm}
	}
	return out
}

// user returns the username of a "user:" subject, and "" for any other.
func (r requestSpec) user() string {
	if name, ok := strings.CutPrefix(r.Subject, "user:"); ok {
		return name
	}
	return ""
}
