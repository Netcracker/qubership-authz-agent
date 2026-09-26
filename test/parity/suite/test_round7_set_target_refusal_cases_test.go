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

// Whether the recorded refusal of missing-attribute-in-set-target came from the
// set target that reads resource.x, or from the fixture beside it.
// missing-attribute-in-set-target uploads two sets whose policies share one
// policyId, since both are built from the key reader, and records 400;
// set-target-reads-unknown-attribute uploads the same target with two policy ids
// and records 200. The two cases here separate the two differences. The first
// repeats missing-attribute-in-set-target with the sibling policy under a key of
// its own, so the policy ids differ and the target is the only thing left to
// refuse; its requests are the recorded case's, read against the sibling set.
// The second uploads two sets whose targets name the resource type alone and
// whose policies share one policyId, so the shared id is the only thing left to
// refuse; its two requests, one per set, are probes that a set the PAP accepted
// answers true.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only, like every regular case.
func (s *ParitySuite) TestRound7SetTargetRefusalCases() {
	s.runRegularCases(setTargetRefusalCases())
}

func setTargetRefusalCases() []regularCase {
	var cases []regularCase

	{
		id := "set-target-reads-missing-attribute-with-distinct-policy-ids"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("reads-missing", "resourceType == '"+rt+"' AND resource.x == 'v'", "DENY_UNLESS_PERMIT",
					[]any{b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil))}, nil),
				b.set("sibling", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT",
					[]any{b.policy("sibling-reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW", nil))}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "sibling-allows", resource: map[string]any{"id": "reg-set-target", "s": "y"}},
				{name: "both-attributes-present", resource: map[string]any{"id": "reg-set-target", "x": "v", "s": "n"}},
			},
		})
	}

	{
		id := "two-sets-whose-policies-share-one-id"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("first", rtTarget, "DENY_UNLESS_PERMIT",
					[]any{b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("first-read-allow", "operation == 'READ'", "true", "ALLOW", nil))}, nil),
				b.set("second", rtTarget, "DENY_UNLESS_PERMIT",
					[]any{b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("second-probe-allow", "operation == 'PROBE'", "true", "ALLOW", nil))}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-under-the-first-set", operation: "READ", resource: map[string]any{"id": "reg-shared-policy-id"}},
				{name: "probe-under-the-second-set", operation: "PROBE", resource: map[string]any{"id": "reg-shared-policy-id"}},
			},
		})
	}

	return cases
}
