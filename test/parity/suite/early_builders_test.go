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

// parityPipMockBase is the pip-mock address as access-control resolves it, the
// same one every PIP fixture under testdata/fixtures spells out. The suite
// reaches the same service through Config.PipMockControlURL, which is a
// different address on a different network.
const parityPipMockBase = "http://pip-mock:8090/api/v1/pip"

// regularPolicySetCases are the cases TestRegularPolicySetCases runs after
// early/regular-policy-set.json, in the order their goldens were recorded. The
// first uploads a simplified policy beside its set and the last two upload two
// set lists, which a case file cannot express; inactive-set runs between them.
func regularPolicySetCases() []regularCase {
	var cases []regularCase

	// A set and a simplified policy for one resource type, in a filter.
	{
		id := "filter-set-beside-simplified-policy"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			simplified: []any{map[string]any{
				"component":             "PARITY",
				"reason":                id,
				"resourceType":          rt,
				"operation":             "LIST",
				"rsqlPredicate":         "simplified==1",
				"roles":                 []string{"ROLE_PARITY_READER"},
				"applicableForFrontend": false,
				"id":                    b.id("simplified"),
			}},
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "regular==1"})),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "filter", filter: true},
				{name: "check-list", operation: "LIST", resource: map[string]any{"id": "reg-mixed"}},
			},
		})
	}

	// Lifecycle: an inactive set, a second upload under the same externalID, and two
	// externalIDs for one resource type.
	{
		id := "inactive-set"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		set := b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
			b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
				b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
		}, nil)
		set["status"] = "INACTIVE"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads:      []regularUpload{{externalID: "parity-" + id, sets: []any{set}}},
			requests:     []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-inactive"}}},
		})
	}
	{
		id := "reupload-replaces-sets"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id, sets: []any{
					b.set("set", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
					}, nil),
				}},
				{externalID: "parity-" + id, sets: []any{
					b.set("set", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil)),
					}, nil),
				}},
			},
			requests: []isolatedRequest{
				{name: "read-from-first-upload", operation: "READ", resource: map[string]any{"id": "reg-reupload"}},
				{name: "update-from-second-upload", operation: "UPDATE", resource: map[string]any{"id": "reg-reupload"}},
			},
		})
	}
	{
		id := "two-external-ids-allow-and-deny"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		rtTarget := "resourceType == '" + rt + "'"
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{
				{externalID: "parity-" + id + "-allow", sets: []any{
					b.set("allow", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("allow-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil)),
					}, nil),
				}},
				{externalID: "parity-" + id + "-deny", sets: []any{
					b.set("deny", rtTarget, "DENY_UNLESS_PERMIT", []any{
						b.policy("deny-reader", readerTarget, "DENY_UNLESS_PERMIT",
							b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil)),
					}, nil),
				}},
			},
			requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-two-sets"}}},
		})
	}

	return cases
}
