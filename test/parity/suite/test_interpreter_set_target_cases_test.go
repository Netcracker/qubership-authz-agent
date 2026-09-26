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

import "strings"

// setTargetService is the value every set target of the set-target cases compares
// resource.service with. It is this group's own, so a set whose target names no
// resource type applies to no request of another case.
const setTargetService = "parity-st-svc"

// Whether the PAP accepts a set whose target reads an attribute of the resource,
// and what such a target does on a request that carries the attribute, one that
// carries another value, one that carries no such attribute, and on a filter
// request, which carries no resource at all.
//
// missing-attribute-in-set-target records that a set target of the form
// resourceType == 'T' AND resource.x == 'v' is refused at upload, while the
// regular policy sets of products put resourceType == 'T' AND resource.service
// == '…' on the set. So either the PAP accepts some resource attributes on a set
// target and refuses others, or the refusal recorded had another cause; the two
// policies of that fixture share one policyId, and
// TestRound7SetTargetRefusalCases records that shape on its own. Each case
// uploads one set with one attribute in its target and records the upload
// status: resource.service, the attribute product sets read; resource.uri under
// MATCH and resource.id, the attributes product rules read; resource.x, the
// control that repeats the recorded refusal; and resource.service with no
// resourceType beside it, the boundary of what a set target has to name.
//
// Under an accepted set, one policy allows READ and LIST without a condition, so
// a request the set target admits is true and a request it does not is false,
// and the filter carries the LIST rule's predicate when the set target lets a
// request with no resource through. A second set on the same resource type
// allows READ when resource.s is 'y', the sibling missing-attribute-in-set-target
// pairs with the reading set: attribute-absent-beside-the-sibling carries s and
// not the attribute the first set reads, so true means the first set was not
// applicable and false means it ended the decision the way a missing attribute
// ends a rule (s10-absent-or-true). attribute-absent, with no sibling to fall
// back on, and the filter request, where the resource is always absent, record
// the same target on its own.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy profile
// only, like every regular case.
func (s *ParitySuite) TestInterpreterSetTargetCases() {
	s.runRegularCases(setTargetCases())
}

func setTargetCases() []regularCase {
	var cases []regularCase

	for _, form := range []struct {
		key string
		// target is the part of the set target that reads the resource; withType
		// says whether resourceType == '<rt>' AND precedes it.
		target   string
		withType bool
		// equal and other are the resource that satisfies the target and the one
		// that carries the attribute with another value; absent carries no such
		// attribute and differs from equal in that alone.
		equal, other, absent map[string]any
	}{
		{
			key: "reads-service", withType: true,
			target: "resource.service == '" + setTargetService + "'",
			equal:  map[string]any{"id": "reg-st", "service": setTargetService},
			other:  map[string]any{"id": "reg-st", "service": "parity-other-svc"},
			absent: map[string]any{"id": "reg-st"},
		},
		{
			key: "reads-uri-with-match", withType: true,
			target: "resource.uri MATCH /parity-st/**",
			equal:  map[string]any{"id": "reg-st", "uri": "/parity-st/items/1"},
			other:  map[string]any{"id": "reg-st", "uri": "/parity-other/items/1"},
			absent: map[string]any{"id": "reg-st"},
		},
		{
			key: "reads-id", withType: true,
			target: "resource.id == 'reg-st-id'",
			equal:  map[string]any{"id": "reg-st-id"},
			other:  map[string]any{"id": "reg-st-other"},
			absent: map[string]any{"a": "y"},
		},
		{
			key: "reads-unknown-attribute", withType: true,
			target: "resource.x == 'v'",
			equal:  map[string]any{"id": "reg-st", "x": "v"},
			other:  map[string]any{"id": "reg-st", "x": "w"},
			absent: map[string]any{"id": "reg-st"},
		},
		{
			key: "reads-service-without-resource-type", withType: false,
			target: "resource.service == '" + setTargetService + "'",
			equal:  map[string]any{"id": "reg-st", "service": setTargetService},
			other:  map[string]any{"id": "reg-st", "service": "parity-other-svc"},
			absent: map[string]any{"id": "reg-st"},
		},
	} {
		id := "set-target-" + form.key
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		setTarget := form.target
		if form.withType {
			setTarget = "resourceType == '" + rt + "' AND " + form.target
		}
		withSibling := map[string]any{"s": "y"}
		for key, value := range form.absent {
			withSibling[key] = value
		}
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", setTarget, "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read", "operation == 'READ'", "true", "ALLOW", nil),
						b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": "st==1"})),
				}, nil),
				b.set("sibling", "resourceType == '"+rt+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("sibling-reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read-when-s", "operation == 'READ'", "resource.s == 'y'", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "attribute-equal", resource: form.equal},
				{name: "attribute-other", resource: form.other},
				{name: "attribute-absent", resource: form.absent},
				{name: "attribute-absent-beside-the-sibling", resource: withSibling},
				{name: "filter", filter: true},
			},
		})
	}

	// A set target that spells the resource type in lower case, against a
	// request in upper case. x28-policy-resource-type-lowercase records that a
	// simplified policy's resource type matches a request whatever the case;
	// the set target is a condition, and the recorded conditions compare case
	// insensitively (c5-string-equals-other-case) but the resourceType operand
	// of a set target is not among them. the-request-in-the-same-case is the
	// control.
	{
		id := "set-target-resource-type-in-lower-case"
		b := regularBuilder{caseID: id}
		rt := regularResourceType(id)
		lower := strings.ToLower(rt)
		cases = append(cases, regularCase{
			id:           id,
			resourceType: rt,
			uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
				b.set("set", "resourceType == '"+lower+"'", "DENY_UNLESS_PERMIT", []any{
					b.policy("reader", readerTarget, "DENY_UNLESS_PERMIT",
						b.rule("read", "operation == 'READ'", "true", "ALLOW", nil)),
				}, nil),
			}}},
			requests: []isolatedRequest{
				{name: "the-request-in-upper-case", typ: rt, resource: map[string]any{"id": "reg-st-case"}},
				{name: "the-request-in-the-same-case", typ: lower, resource: map[string]any{"id": "reg-st-case"}},
			},
		})
	}

	return cases
}
