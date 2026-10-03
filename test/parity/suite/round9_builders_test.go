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

// The builders and PIP declarations below were written for round 9, whose cases
// are now data under testdata/cases/round9, and later rounds still build their
// Go cases with them.

// round9NoHeaderPIP is a HEADER PIP whose header no case sends and that has no
// defaultValue.
var round9NoHeaderPIP = map[string]any{
	"name":      "subject.parityR9NoHeader",
	"type":      "UUID",
	"pipType":   "HEADER",
	"header":    "x-parity-r9-no-such-header",
	"cacheable": false,
}

// round9NoClaimPIP is a TOKEN PIP over a claim the reader's token does not carry,
// with no defaultValue.
var round9NoClaimPIP = map[string]any{
	"name":      "subject.parityR9NoClaim",
	"type":      "UUID",
	"pipType":   "TOKEN",
	"claim":     "parity_r9_no_such_claim",
	"cacheable": false,
}

// round9FalseSubjectCondition is a condition over the subject alone that is false
// for parity-reader, so a filter request, which carries no resource, evaluates it.
const round9FalseSubjectCondition = "subject.roles CONTAINS 'ROLE_PARITY_NOBODY'"

// round9FilterRequests are the filter on LIST and check/resource on LIST, the
// decision the same rules produce.
var round9FilterRequests = []isolatedRequest{
	{name: "filter", filter: true},
	{name: "check-list", operation: "LIST", resource: map[string]any{"id": "r9-filter"}},
}

// round9SetCase builds a case of one set under setAlgorithm holding policies,
// each built by the case's builder, and sends round9FilterRequests.
func round9SetCase(id, setAlgorithm string, policies func(b regularBuilder) []any) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", setAlgorithm, policies(b), nil),
		}}},
		requests: round9FilterRequests,
	}
}

// round9PolicyCase is round9SetCase with the set under DENY_UNLESS_PERMIT and one
// policy under policyAlgorithm holding rules.
func round9PolicyCase(id, policyAlgorithm string, rules func(b regularBuilder) []any) regularCase {
	return round9SetCase(id, "DENY_UNLESS_PERMIT", func(b regularBuilder) []any {
		return []any{b.policy("reader", readerTarget, policyAlgorithm, rules(b)...)}
	})
}

// round9PredicatePolicy is a DENY_UNLESS_PERMIT policy whose one rule allows LIST
// with the predicate allowed==1.
func round9PredicatePolicy(b regularBuilder) map[string]any {
	return b.policy("with-a-predicate", readerTarget, "DENY_UNLESS_PERMIT", allowWithPredicate(b, "list-with-a-predicate", "allowed==1"))
}

// allowWithPredicate is an ALLOW rule on LIST whose predicate is rsql.
func allowWithPredicate(b regularBuilder, key, rsql string) map[string]any {
	return b.rule(key, "operation == 'LIST'", "true", "ALLOW", map[string]string{"rsqlPredicate": rsql})
}

// round9OneHeader is the header round9OneHeaderPIP reads.
const round9OneHeader = "x-parity-r9-one"

// round9OneHeaderPIP is a HEADER PIP over round9OneHeader, with no
// defaultValue.
var round9OneHeaderPIP = map[string]any{
	"name": "subject.parityR9OneHeader", "type": "UUID", "pipType": "HEADER", "header": round9OneHeader, "cacheable": false,
}
