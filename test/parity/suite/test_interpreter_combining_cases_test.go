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

// acceptedAlgorithms are the combining algorithms the PAP loads
// (load-policy-sets-v1/regular/algorithm-*); the other six names are refused.
var acceptedAlgorithms = []struct{ key, name string }{
	{"deny-unless-permit", "DENY_UNLESS_PERMIT"},
	{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
	{"deny-overrides", "DENY_OVERRIDES"},
	{"permit-overrides", "PERMIT_OVERRIDES"},
}

// What a policy contributes to its set when it has no rule that applies, and what
// a nested set contributes to its parent in the same state. The recorded
// algorithm-* cases give the set and its one policy the same algorithm and see
// only the set's answer, so they do not separate a policy that answers deny from
// a policy that is not applicable: under DENY_UNLESS_PERMIT both read as false,
// and under PERMIT_UNLESS_DENY both read as true. The two outcomes differ once the
// set combines the policy with a neighbor, and an evaluator of regular sets has to
// pick one.
//
// Each case below gives the set an algorithm that reacts to the difference and
// sends the operation the policy has no rule for. Every case also sends an
// operation a live rule decides, so a set that was never consulted is told from a
// set that answered.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterCombiningCases() {
	s.runRegularCases(combiningCases())
}

func combiningCases() []regularCase {
	var cases []regularCase

	// Two DENY_UNLESS_PERMIT policies under DENY_OVERRIDES, each allowing one
	// operation. READ reaches an ALLOW in the second policy and no rule in the
	// first: false means the first policy answered deny and the set let it override;
	// true means the first policy was not applicable. PROBE has an ALLOW in both
	// policies and is the control.
	{
		id := "policy-without-a-rule-under-deny-overrides"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_OVERRIDES", []any{
					b.policy("creates", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("create-allow", "operation == 'CREATE'", "true", "ALLOW", nil),
						b.rule("probe-allow-first", "operation == 'PROBE'", "true", "ALLOW", nil)),
					b.policy("reads", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
						b.rule("probe-allow-second", "operation == 'PROBE'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-allowed-by-one-policy-without-a-rule-in-the-other", operation: "READ", resource: map[string]any{"id": "reg-mixed-do"}},
				{name: "probe-allowed-by-both-policies", operation: "PROBE", resource: map[string]any{"id": "reg-mixed-do"}},
			},
		})
	}

	// The same two policies and requests, with the first policy under
	// DENY_OVERRIDES of its own. The algorithm-* cases record a policy with no
	// rule under its own DENY_OVERRIDES only as the lone policy of a
	// DENY_OVERRIDES set, where a denial and inapplicability both read false;
	// beside a policy that allows READ the two read apart.
	{
		id := "policy-without-a-rule-under-its-own-deny-overrides"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_OVERRIDES", []any{
					b.policy("creates", readerTarget, "DENY_OVERRIDES",
						b.rule("create-allow", "operation == 'CREATE'", "true", "ALLOW", nil),
						b.rule("probe-allow-first", "operation == 'PROBE'", "true", "ALLOW", nil)),
					b.policy("reads", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
						b.rule("probe-allow-second", "operation == 'PROBE'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-allowed-by-one-policy-without-a-rule-in-the-other", operation: "READ", resource: map[string]any{"id": "reg-mixed-do-own"}},
				{name: "probe-allowed-by-both-policies", operation: "PROBE", resource: map[string]any{"id": "reg-mixed-do-own"}},
			},
		})
	}

	// One DENY_UNLESS_PERMIT policy under PERMIT_UNLESS_DENY. READ reaches no rule:
	// false means the policy's default deny counts as a denial; true means the
	// policy was not applicable and the set permitted by default. CREATE reaches
	// the ALLOW and DELETE the DENY; both are controls.
	{
		id := "policy-without-a-rule-under-permit-unless-deny"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
					b.policy("creates", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("create-allow", "operation == 'CREATE'", "true", "ALLOW", nil),
						b.rule("delete-deny", "operation == 'DELETE'", "true", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-without-a-rule", operation: "READ", resource: map[string]any{"id": "reg-mixed-pud"}},
				{name: "create-allowed", operation: "CREATE", resource: map[string]any{"id": "reg-mixed-pud"}},
				{name: "delete-denied", operation: "DELETE", resource: map[string]any{"id": "reg-mixed-pud"}},
			},
		})
	}

	// The same question one level up: a nested set whose only policy has no rule
	// for READ, under each accepted inner algorithm and under the two outer
	// algorithms that react to the difference. Under PERMIT_UNLESS_DENY the outer
	// set holds nothing else, so READ is true when the inner set is not applicable
	// and false when it contributes its default denial. Under DENY_OVERRIDES the
	// outer set holds a policy that allows READ, so READ is true when the inner set
	// contributes no denial. An inner PERMIT_UNLESS_DENY permits READ by default and
	// is the column where both readings answer true; it is the control for the
	// other three. nested-outer-deny-inner-allow-* records the outer
	// PERMIT_OVERRIDES and DENY_UNLESS_PERMIT, where a not-applicable child and a
	// denying child read the same.
	for _, outer := range []struct{ key, name string }{
		{"permit-unless-deny", "PERMIT_UNLESS_DENY"},
		{"deny-overrides", "DENY_OVERRIDES"},
	} {
		for _, inner := range acceptedAlgorithms {
			id := "nested-no-rule-" + inner.key + "-in-" + outer.key
			b := regularBuilder{caseID: id}
			rt := regularResourceType(id)
			rtTarget := "resourceType == '" + rt + "'"
			outerPolicies := []any{}
			if outer.name == "DENY_OVERRIDES" {
				outerPolicies = []any{b.policy("outer-reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("outer-read-allow", "operation == 'READ'", "true", "ALLOW", nil))}
			}
			cases = append(cases, regularCase{
				id:           id,
				resourceType: rt,
				uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
					b.set("outer", rtTarget, outer.name, outerPolicies,
						[]any{b.set("inner", rtTarget, inner.name,
							[]any{b.policy("inner-reader", readerTarget, inner.name,
								b.rule("inner-create-allow", "operation == 'CREATE'", "true", "ALLOW", nil))},
							nil)}),
				}}},
				requests: []isolatedRequest{
					{name: "read-without-a-rule-in-the-inner-set", operation: "READ", resource: map[string]any{"id": "reg-mixed-nested"}},
					{name: "create-allowed-by-the-inner-set", operation: "CREATE", resource: map[string]any{"id": "reg-mixed-nested"}},
				},
			})
		}
	}

	// A policy whose target is false, holding a DENY that would apply, under
	// PERMIT_UNLESS_DENY. True means the target keeps the policy out of the
	// combination; false means the policy was combined and its denial counted. The
	// control policy is PERMIT_UNLESS_DENY itself, so that it never contributes a
	// default denial of its own to READ, and its DELETE denial shows the set is
	// evaluated. deny-policy-target-does-not-match asks the same under
	// DENY_OVERRIDES, where a not-applicable policy and a permitting one read the
	// same.
	{
		id := "policy-with-a-false-target-under-permit-unless-deny"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
					b.policy("nobody", "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'", "DENY_UNLESS_PERMIT",
						b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil)),
					b.policy("reader", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("delete-deny", "operation == 'DELETE'", "true", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-denied-only-under-the-false-target", operation: "READ", resource: map[string]any{"id": "reg-mixed-target"}},
				{name: "delete-denied-under-the-true-target", operation: "DELETE", resource: map[string]any{"id": "reg-mixed-target"}},
			},
		})
	}

	// Every pair of distinct accepted algorithms, one on the set and one on its
	// policy, over the rules and the six requests of the algorithm-* cases. The
	// twelve cases fill in the table those four cases record the diagonal of.
	for _, setAlgorithm := range acceptedAlgorithms {
		for _, policyAlgorithm := range acceptedAlgorithms {
			if setAlgorithm.name == policyAlgorithm.name {
				continue
			}
			id := "set-" + setAlgorithm.key + "-policy-" + policyAlgorithm.key
			b := regularBuilder{caseID: id}
			rt := regularResourceType(id)
			cases = append(cases, regularCase{
				id:           id,
				resourceType: rt,
				uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
					b.set("set", "resourceType == '"+rt+"'", setAlgorithm.name, []any{
						b.policy("reader", readerTarget, policyAlgorithm.name,
							b.rule("read-allow", "operation == 'READ'", "true", "ALLOW", nil),
							b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil),
							b.rule("update-deny", "operation == 'UPDATE'", "true", "DENY", nil),
							b.rule("update-allow", "operation == 'UPDATE'", "true", "ALLOW", nil),
							b.rule("delete-deny", "operation == 'DELETE'", "true", "DENY", nil),
							b.rule("approve-allow-missing-attribute", "operation == 'APPROVE'", "resource.x == 'v'", "ALLOW", nil),
							b.rule("approve-allow", "operation == 'APPROVE'", "true", "ALLOW", nil),
							b.rule("reject-deny-missing-attribute", "operation == 'REJECT'", "resource.x == 'v'", "DENY", nil),
							b.rule("reject-allow", "operation == 'REJECT'", "true", "ALLOW", nil),
						),
					}, nil),
				}}},
				requests: []isolatedRequest{
					{name: "read-allow-then-deny", operation: "READ", resource: map[string]any{"id": "reg-mixed-alg"}},
					{name: "update-deny-then-allow", operation: "UPDATE", resource: map[string]any{"id": "reg-mixed-alg"}},
					{name: "delete-deny-alone", operation: "DELETE", resource: map[string]any{"id": "reg-mixed-alg"}},
					{name: "create-no-rule", operation: "CREATE", resource: map[string]any{"id": "reg-mixed-alg"}},
					{name: "approve-failed-allow-beside-allow", operation: "APPROVE", resource: map[string]any{"id": "reg-mixed-alg"}},
					{name: "reject-failed-deny-beside-allow", operation: "REJECT", resource: map[string]any{"id": "reg-mixed-alg"}},
				},
			})
		}
	}

	// PERMIT_OVERRIDES over a policy that permits by default beside a policy that
	// denies. On the recorded requests PERMIT_OVERRIDES and DENY_UNLESS_PERMIT
	// answer alike; here the permit comes from a deny list that did not fire rather
	// than from an ALLOW rule, and DELETE, denied by the same deny list, is the
	// control.
	{
		id := "permit-overrides-over-a-default-permit-and-a-deny"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_OVERRIDES", []any{
					b.policy("deny-list", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("delete-deny", "operation == 'DELETE'", "true", "DENY", nil)),
					b.policy("denies-read", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-deny", "operation == 'READ'", "true", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "read-permitted-by-default-and-denied-by-a-rule", operation: "READ", resource: map[string]any{"id": "reg-mixed-po"}},
				{name: "delete-denied-by-both-policies", operation: "DELETE", resource: map[string]any{"id": "reg-mixed-po"}},
			},
		})
	}

	return cases
}
