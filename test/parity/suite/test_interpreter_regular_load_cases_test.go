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

// Which of the forms the simplified-policy upload refuses are refused in a rule of
// a regular set as well. The simplified upload refuses all four: subject.isM2M
// (g8a-subject-is-m2m), an undeclared subject attribute
// (x19-undeclared-subject-attribute), operation as an operand
// (o1-operation-operand), although operation stands in every rule target, and
// subject.permissions.PARITY (pm2-mapping-pip-suffixed-reference). Nothing records
// the same four forms through the policy-set upload, which has a validator of its
// own.
//
// Each case records the upload status and, for an accepted set, one READ. The
// reader is an end user, carries no declared attribute of the name parityUnknown,
// and holds no permission from a PIP this domain declares, so the READ of an
// accepted set records what the form evaluates to for a subject it does not
// describe.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterRegularLoadCases() {
	var cases []regularCase
	for _, form := range []struct{ key, condition string }{
		{"subject-is-m2m", "subject.isM2M == true"},
		{"undeclared-subject-attribute", "subject.parityUnknown == 'x'"},
		{"operation-in-a-condition", "operation == 'READ'"},
		{"suffixed-permissions", "subject.permissions.PARITY CONTAINS 'parity_permission'"},
	} {
		id := "rule-condition-" + form.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-allow", "operation == 'READ'", form.condition, "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "reg-load-" + form.key}}},
		})
	}
	s.runRegularCases(cases)
}
