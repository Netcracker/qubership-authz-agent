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

import "fmt"

// What subject allowed 'OP' on resource and subject denied 'OP' on resource
// evaluate when a policy for OP exists. u7-has-access and u12-subject-denied
// record false for both, on a lone READ policy whose condition names READ: the
// nested decision is the policy's own, so the false there is a decision that
// refers to itself, cut off or refused, and says nothing about the operator over
// a policy for another operation. The two forms are either a decision for
// another operation on the same resource, read from inside a condition, or
// accepted and always false; the recorded cases cannot tell.
//
// access-operator-reads-another-operation holds a READ rule with a condition
// on resource.a and an UPDATE rule whose condition is subject allowed 'READ' on
// resource, and a DELETE rule whose condition is subject denied 'READ'. UPDATE
// with a = y and a = n decides as READ would if the operator evaluates the READ
// decision, and false under both if the form is always false; DELETE is the
// negated twin; READ under both values is the control that the READ rule
// itself decides on a.
//
// access-operator-chain holds six operations where each one's rule is subject
// allowed on the next, ending in a READ rule that allows without a condition.
// PARITY_OP1 needs six nested decisions and PARITY_OP6 one; the answers record
// where the nesting is cut off, if anywhere.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterAccessOperatorCases() {
	s.runRegularCases(accessOperatorCases())
}

func accessOperatorCases() []regularCase {
	var cases []regularCase

	{
		id := "access-operator-reads-another-operation"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-when-a", "operation == 'READ'", "resource.a == 'y'", "ALLOW", nil),
						b.rule("update-if-read-allowed", "operation == 'UPDATE'", "subject allowed 'READ' on resource", "ALLOW", nil),
						b.rule("delete-if-read-denied", "operation == 'DELETE'", "subject denied 'READ' on resource", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "update-when-read-is-allowed", operation: "UPDATE", resource: map[string]any{"id": "reg-ao", "a": "y"}},
				{name: "update-when-read-is-denied", operation: "UPDATE", resource: map[string]any{"id": "reg-ao", "a": "n"}},
				{name: "delete-when-read-is-allowed", operation: "DELETE", resource: map[string]any{"id": "reg-ao", "a": "y"}},
				{name: "delete-when-read-is-denied", operation: "DELETE", resource: map[string]any{"id": "reg-ao", "a": "n"}},
				{name: "read-allowed", operation: "READ", resource: map[string]any{"id": "reg-ao", "a": "y"}},
				{name: "read-denied", operation: "READ", resource: map[string]any{"id": "reg-ao", "a": "n"}},
			},
		})
	}

	{
		id := "access-operator-chain"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		const depth = 6
		rules := []any{b.rule("read", "operation == 'READ'", "true", "ALLOW", nil)}
		for i := depth; i >= 1; i-- {
			next := "READ"
			if i < depth {
				next = fmt.Sprintf("PARITY_OP%d", i+1)
			}
			rules = append(rules, b.rule(fmt.Sprintf("op%d", i), fmt.Sprintf("operation == 'PARITY_OP%d'", i),
				fmt.Sprintf("subject allowed '%s' on resource", next), "ALLOW", nil))
		}
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT", rules...),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "six-nested-decisions", operation: "PARITY_OP1", resource: map[string]any{"id": "reg-ao-chain"}},
				{name: "five-nested-decisions", operation: "PARITY_OP2", resource: map[string]any{"id": "reg-ao-chain"}},
				{name: "four-nested-decisions", operation: "PARITY_OP3", resource: map[string]any{"id": "reg-ao-chain"}},
				{name: "three-nested-decisions", operation: "PARITY_OP4", resource: map[string]any{"id": "reg-ao-chain"}},
				{name: "two-nested-decisions", operation: "PARITY_OP5", resource: map[string]any{"id": "reg-ao-chain"}},
				{name: "one-nested-decision", operation: "PARITY_OP6", resource: map[string]any{"id": "reg-ao-chain"}},
			},
		})
	}

	return cases
}
