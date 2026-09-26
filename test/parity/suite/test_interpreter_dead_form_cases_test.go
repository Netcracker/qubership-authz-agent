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

// What a form that is always false alone does to the rest of its condition and to
// the rules beside it. Four forms are recorded as accepted by the PAP and false for
// a value they describe: resource['x'] == 'v' (j7-bracket-path), resource.x != null
// (x26-null-literal/attribute-present), MATCH against a pattern taken from an
// attribute (a2-match-attribute-pattern) and MATCH against a /…/ regex literal
// (x34-regex-literal). Alone, a leaf that is false and a rule that was ended look
// the same, and the two readings differ for every policy that has an OR, a DENY
// rule, or a second ALLOW rule beside the form. subject allowed 'READ' on resource
// (u7-has-access) is recorded false too, on a policy whose condition refers to
// the policy's own decision; TestInterpreterAccessOperatorCases sends it beside
// a policy for the operation it names.
//
// The df cases put each form through orProbePair: a true probe means the form is a
// false leaf and OR went on to resource.a == 'y'; a false probe means the form
// ended the rule the way an absent key does (s10-absent-or-true).
//
// The two regular cases ask the same of the levels above the condition. Under
// PERMIT_UNLESS_DENY a DENY rule whose condition is the form OR a true operand
// denies when the form is a false leaf and does not apply when it ends the rule;
// beside an ALLOW rule of its own, a rule holding the form is expected to leave the
// neighbor alone, the way approve-failed-allow-beside-allow records for an absent
// key. Each regular case sends a request where nothing depends on the form as its
// control.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterDeadFormCases() {
	probe := isolatedRequest{name: "form-is-false-and-the-right-operand-true", resource: map[string]any{"id": "dead-form", "a": "y", "x": "abc", "p": "ab*"}}

	var cases []isolatedCase
	cases = append(cases, orProbePair("df1-bracket-path", "PARITY_SUITE_DEAD_DF1", "resource['x'] == 'v'", probe)...)
	cases = append(cases, orProbePair("df2-null-literal", "PARITY_SUITE_DEAD_DF2", "resource.x != null", probe)...)
	cases = append(cases, orProbePair("df3-match-against-an-attribute", "PARITY_SUITE_DEAD_DF3", "resource.x MATCH resource.p", probe)...)
	cases = append(cases, orProbePair("df4-match-against-a-regex-literal", "PARITY_SUITE_DEAD_DF4", "resource.x MATCH /ab.*/", probe)...)
	s.runIsolatedCases(cases)

	// runRegularCases skips the whole test on the authz-agent profile, and the
	// isolated cases above have run on it by then.
	if !isAuthzAgentProfile(s.cfg.Profile) {
		s.runRegularCases(deadFormRegularCases())
	}
}

func deadFormRegularCases() []regularCase {
	var cases []regularCase

	// A DENY rule whose condition is a dead form OR a true operand, under the
	// algorithm that permits what no rule denied. form-beside-a-true-operand is the
	// question; nothing-denies is the control that the set permits by default.
	{
		id := "dead-form-in-a-deny-rule"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
					b.policy("reader", readerTarget, "PERMIT_UNLESS_DENY",
						b.rule("read-deny", "operation == 'READ'", "resource.x != null OR resource.a == 'y'", "DENY", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "form-beside-a-true-operand", resource: map[string]any{"id": "reg-dead-deny", "x": "abc", "a": "y"}},
				{name: "nothing-denies", resource: map[string]any{"id": "reg-dead-deny", "x": "abc", "a": "n"}},
			},
		})
	}

	// An ALLOW rule whose condition is a dead form, beside an ALLOW rule that
	// applies. the-neighbor-allows is the question; the-neighbor-does-not is the
	// control that the set denies when no rule allows.
	{
		id := "dead-form-beside-an-allowing-rule"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow-dead-form", "operation == 'READ'", "resource.x != null", "ALLOW", nil),
						b.rule("read-allow", "operation == 'READ'", "resource.a == 'y'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "the-neighbor-allows", resource: map[string]any{"id": "reg-dead-allow", "x": "abc", "a": "y"}},
				{name: "the-neighbor-does-not", resource: map[string]any{"id": "reg-dead-allow", "x": "abc", "a": "n"}},
			},
		})
	}

	return cases
}
