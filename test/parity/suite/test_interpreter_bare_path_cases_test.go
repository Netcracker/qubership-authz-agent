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

// Whether a path with no resource. prefix names an attribute of the resource.
// Every recorded condition reads the resource as resource.<path>, and the agent's
// own condition parser accepts nothing else; a bare a == 'y' is either the same
// attribute or a form the PAP refuses. Each case records the upload status and,
// for an accepted policy, one request the condition holds for and one it does
// not, so an accepted form that is never evaluated (false under both) is told
// from one that reads the resource.
//
// bp1 compares a bare one-segment path with a literal, bp2 a bare two-segment
// path with subject.id, the shape a rule that reads the owner takes;
// bare-path-in-a-regular-set repeats bp1 in the rule of a regular set, since the
// two uploads have validators of their own.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestInterpreterBarePathCases() {
	s.runIsolatedCases([]isolatedCase{
		{id: "bp1-bare-path-against-a-literal", resourceType: "PARITY_SUITE_BARE_BP1", condition: "a == 'y'", requests: []isolatedRequest{
			{name: "attribute-equal", resource: map[string]any{"id": "bare-bp1", "a": "y"}},
			{name: "attribute-other", resource: map[string]any{"id": "bare-bp1", "a": "n"}},
		}},
		{id: "bp2-bare-nested-path-against-subject-id", resourceType: "PARITY_SUITE_BARE_BP2", condition: "owner.id == subject.id", requests: []isolatedRequest{
			{name: "owner-is-the-reader", resource: map[string]any{"id": "bare-bp2", "owner": map[string]any{"id": parityReaderSubjectID}}},
			{name: "owner-is-someone-else", resource: map[string]any{"id": "bare-bp2", "owner": map[string]any{"id": "00000000-0000-0000-0000-0000000000ee"}}},
		}},
	})

	// runRegularCases skips the whole test on the authz-agent profile, and the
	// isolated cases above have run on it by then.
	if !isAuthzAgentProfile(s.cfg.Profile) {
		s.runRegularCases(barePathRegularCases())
	}
}

func barePathRegularCases() []regularCase {
	id := "bare-path-in-a-regular-set"
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return []regularCase{{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
				b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
					b.rule("read-when-a", "operation == 'READ'", "a == 'y'", "ALLOW", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{
			{name: "attribute-equal", resource: map[string]any{"id": "reg-bare", "a": "y"}},
			{name: "attribute-other", resource: map[string]any{"id": "reg-bare", "a": "n"}},
		},
	}}
}
