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
	"net/http"
	"strings"
)

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

// emptyStateOperators are the operators of the operator-by-state table, each
// with the operand it is written with. A string literal is v, a value neither
// source can hold; < compares with the number 5 and MATCH with the pattern v*.
var emptyStateOperators = []struct{ key, operator string }{
	{"equals", "== 'v'"},
	{"not-equals", "!= 'v'"},
	{"less-than", "< 5"},
	{"is-null", "IS NULL"},
	{"is-not-null", "IS NOT NULL"},
	{"is-empty", "IS EMPTY"},
	{"is-not-empty", "IS NOT EMPTY"},
	{"in", "IN 'v', 'w'"},
	{"not-in", "NOT IN 'v', 'w'"},
	{"contains", "CONTAINS 'v'"},
	{"not-contains", "NOT CONTAINS 'v'"},
	{"match", "MATCH v*"},
	{"not-match", "NOT MATCH v*"},
	{"contains-any", "CONTAINS ANY 'v', 'w'"},
	{"not-contains-any", "NOT CONTAINS ANY 'v', 'w'"},
	{"is-subset", "IS SUBSET 'v', 'w'"},
	{"is-not-subset", "IS NOT SUBSET 'v', 'w'"},
}

// What each operator answers over a HEADER PIP whose header is absent and over a
// TOKEN PIP whose claim is absent, both with no defaultValue. The recorded cells
// are three for the header, != and IS NULL and IS EMPTY all true (h1, h2,
// hl3/no-header), and three for the claim, == false, != true and IS NULL true
// (p1a-p1c). The header answers IS EMPTY true, which null does not, so the
// absent header may be an empty list; the two readings differ under NOT
// CONTAINS, NOT CONTAINS ANY and IS NOT EMPTY, and no case asks them. The
// agent's condition parser accepts every condition here.
//
// Each operator is asked twice per source. Alone, a true answer is the leaf's
// value; a false answer is a false leaf or an aborted rule. Through
// orProbePair, the probe tells those two apart and its control, with the
// operands swapped, is true unless the fixture is broken.
//
// empty-collection-is-null asks IS NULL over an empty resource collection, the
// value an absent header would be read as, with an absent key as the control
// (s6a records it true). empty-header-in-a-predicate renders the absent header
// through an rsql placeholder of a simplified policy, with the header sent as
// the control; p5 records an absent claim there as an empty string.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9EmptyHeaderAndClaimCases() {
	resource := map[string]any{"id": "r9-empty", "a": "y"}
	var cases []isolatedCase
	for _, source := range []struct {
		key string
		pip map[string]any
	}{
		{"absent-header", round9NoHeaderPIP},
		{"absent-claim", round9NoClaimPIP},
	} {
		name := source.pip["name"].(string)
		for _, op := range emptyStateOperators {
			id := "es-" + source.key + "-" + op.key
			rt := "PARITY_SUITE_R9_ES_" + strings.ToUpper(strings.ReplaceAll(source.key+"_"+op.key, "-", "_"))
			operand := name + " " + op.operator
			cases = append(cases, isolatedCase{id: id + "-alone", resourceType: rt + "_ALONE", condition: operand,
				pips: []any{source.pip}, requests: []isolatedRequest{{name: "reader", resource: resource}}})
			pair := orProbePair(id, rt, operand, isolatedRequest{name: "reader", resource: resource})
			for i := range pair {
				pair[i].pips = []any{source.pip}
			}
			cases = append(cases, pair...)
		}
	}
	cases = append(cases,
		isolatedCase{id: "es-empty-collection-is-null", resourceType: "PARITY_SUITE_R9_ES_EMPTY_COLLECTION", condition: "resource.x IS NULL", requests: []isolatedRequest{
			{name: "empty-collection", resource: map[string]any{"id": "r9-empty", "x": []string{}}},
			{name: "key-absent", resource: map[string]any{"id": "r9-empty"}},
		}},
		isolatedCase{id: "es-empty-header-in-a-predicate", resourceType: "PARITY_SUITE_R9_ES_HEADER_PREDICATE", operation: "LIST", rsql: "a==${subject.parityR9NoHeader}",
			pips: []any{round9NoHeaderPIP}, requests: []isolatedRequest{
				{name: "no-header", filter: true},
				{name: "header-sent", filter: true, headers: map[string]string{"x-parity-r9-no-such-header": "h1"}},
			}},
	)
	s.runIsolatedCases(cases)
}

// round9RightFailedRoute is the pip-mock path of round9RightFailedPIP.
const round9RightFailedRoute = "/api/v1/pip/r9-right-failed"

// round9RightFailedPIP is a GENERAL PIP pinned to answer 500 for
// TestRound9RightOperandCases alone.
var round9RightFailedPIP = map[string]any{
	"name":              "subject.parityR9RightFailed",
	"url":               parityPipMockBase + "/r9-right-failed",
	"httpMethod":        "POST",
	"pipType":           "GENERAL",
	"requestAttributes": map[string]string{"resourceType": "PARITY_SUITE_R9_RIGHT"},
	"cacheable":         false,
}

// round9HomeIDsPIP and round9DelegatedIDsPIP are two HEADER PIPs a condition
// reads on the right of IN, one per header.
var (
	round9HomeIDsPIP = map[string]any{
		"name": "subject.parityR9HomeIds", "type": "UUID", "pipType": "HEADER", "header": "x-parity-r9-home-ids", "cacheable": false,
	}
	round9DelegatedIDsPIP = map[string]any{
		"name": "subject.parityR9DelegatedIds", "type": "UUID", "pipType": "HEADER", "header": "x-parity-r9-delegated-ids", "cacheable": false,
	}
)

// What a condition answers when the attribute on the right of an operator is an
// absent header, an absent claim, or a GENERAL PIP that answered 500. a1 records
// an absent resource key on the right as false alone, which does not tell a
// false leaf from an aborted rule; no case puts a PIP there. The agent's
// condition parser accepts every condition here.
//
// ro-in-an-absent-header, ro-equals-an-absent-claim and ro-in-a-failed-pip go
// through orProbePair: the probe is true when the
// right operand is a value the operator is false over, and false when it ends
// the rule or, for the failed PIP, the whole answer. The failed PIP is read by
// the probe alone, since the control's left operand is true; the pip-mock call
// log is read after the cases, and a call has to be there, or a false probe is
// a declaration the stand ignored rather than a failed PIP.
//
// in-either-header is the one condition of the product policies in reach whose
// OR could depend on how the right operand of IN resolves:
// resource.customerId IN one header OR resource.customerId IN another. With
// only the second header sent, the first IN reads an absent header, and the
// answer is true when that IN is false and OR goes on. only-home-holds-the-id is
// the control, true whatever the second IN does, and neither-header-holds-the-id
// the negative control.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9RightOperandCases() {
	ctx := context.Background()
	s.Require().NoError(s.pipMock.PinRoute(ctx, round9RightFailedRoute, PipStubResponse{
		StatusCode: http.StatusInternalServerError,
		Body:       map[string]string{"error": "parity right-operand case"},
	}))
	s.Require().NoError(s.pipMock.ResetCalls(ctx))

	resource := map[string]any{"id": "r9-right", "a": "y", "x": "v"}
	var cases []isolatedCase
	for _, form := range []struct {
		key, operand string
		pip          map[string]any
	}{
		{"in-an-absent-header", "resource.x IN subject.parityR9NoHeader", round9NoHeaderPIP},
		{"equals-an-absent-claim", "resource.x == subject.parityR9NoClaim", round9NoClaimPIP},
		{"in-a-failed-pip", "resource.x IN subject.parityR9RightFailed", round9RightFailedPIP},
	} {
		pair := orProbePair("ro-"+form.key, "PARITY_SUITE_R9_RO_"+strings.ToUpper(strings.ReplaceAll(form.key, "-", "_")),
			form.operand, isolatedRequest{name: "reader", resource: resource})
		for i := range pair {
			pair[i].pips = []any{form.pip}
		}
		cases = append(cases, pair...)
	}
	customer := map[string]any{"id": "r9-right", "customerId": "c1"}
	cases = append(cases, isolatedCase{
		id:           "ro-in-either-header",
		resourceType: "PARITY_SUITE_R9_RO_IN_EITHER_HEADER",
		condition:    "resource.customerId IN subject.parityR9HomeIds OR resource.customerId IN subject.parityR9DelegatedIds",
		pips:         []any{round9HomeIDsPIP, round9DelegatedIDsPIP},
		requests: []isolatedRequest{
			{name: "only-delegated-holds-the-id", resource: customer, headers: map[string]string{"x-parity-r9-delegated-ids": "c1"}},
			{name: "only-home-holds-the-id", resource: customer, headers: map[string]string{"x-parity-r9-home-ids": "c1"}},
			{name: "neither-header-holds-the-id", resource: customer, headers: map[string]string{"x-parity-r9-home-ids": "c2", "x-parity-r9-delegated-ids": "c3"}},
		},
	})
	s.runIsolatedCases(cases)

	s.Run("ro-in-a-failed-pip/the-pip-calls", func() {
		calls, err := s.pipMock.GetCalls(ctx)
		s.Require().NoError(err)
		read := 0
		for _, call := range calls {
			if call.Path == round9RightFailedRoute {
				read++
			}
		}
		s.Assert().Positive(read, "pip-mock calls to %s over the right-operand cases", round9RightFailedRoute)
	})
}

// round9OneHeader is the header the HEADER PIP of the single-element cases reads.
const round9OneHeader = "x-parity-r9-one"

var (
	// round9OneHeaderPIP reads round9OneHeader, which the cases send holding one
	// value.
	round9OneHeaderPIP = map[string]any{
		"name": "subject.parityR9OneHeader", "type": "UUID", "pipType": "HEADER", "header": round9OneHeader, "cacheable": false,
	}
	// round9OneRolePIP selects the reader's one parity role out of the realm
	// roles, a claim that is a list of one element.
	round9OneRolePIP = map[string]any{
		"name": "subject.parityR9OneRole", "type": "UUID", "pipType": "TOKEN",
		"claim": "$.realm_access.roles[?(@ == 'ROLE_PARITY_READER')]", "cacheable": false,
	}
)

// What ==, != and IN answer over a HEADER PIP whose header holds one value, and
// over a TOKEN PIP whose claim is a list of one element. hl1-hl3 record that a
// header is split on commas into a list, and == 'a,b' over the header a,b is
// false; no case asks == over a header holding a single value, the form every
// header of the product policies in reach is sent in. The agent's condition
// parser accepts every condition here.
//
// Each header case is sent the header a, the value the operator is asked
// about, and the header b, the other partition. sl-header-contains is the control:
// true over a, whichever way the header is read. The claim cases select the
// reader's role through a filter expression, so the claim is a list of one;
// sl-claim-contains is their control. tk2 records only a plain path into the
// token, so a refused upload of the claim cases is a refused filter expression.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9SingleElementListCases() {
	headerRequests := []isolatedRequest{
		{name: "header-a", resource: map[string]any{"id": "r9-one"}, headers: map[string]string{round9OneHeader: "a"}},
		{name: "header-b", resource: map[string]any{"id": "r9-one"}, headers: map[string]string{round9OneHeader: "b"}},
	}
	claimRequests := []isolatedRequest{{name: "reader", resource: map[string]any{"id": "r9-one"}}}
	var cases []isolatedCase
	for _, form := range []struct{ key, operator string }{
		{"equals", "== 'a'"},
		{"not-equals", "!= 'a'"},
		{"in", "IN 'a', 'z'"},
		{"contains", "CONTAINS 'a'"},
	} {
		cases = append(cases, isolatedCase{
			id: "sl-header-" + form.key, resourceType: "PARITY_SUITE_R9_SL_HEADER_" + strings.ToUpper(strings.ReplaceAll(form.key, "-", "_")),
			condition: "subject.parityR9OneHeader " + form.operator, pips: []any{round9OneHeaderPIP}, requests: headerRequests,
		})
	}
	for _, form := range []struct{ key, operator string }{
		{"equals", "== 'ROLE_PARITY_READER'"},
		{"not-equals", "!= 'ROLE_PARITY_READER'"},
		{"in", "IN 'ROLE_PARITY_READER', 'ROLE_PARITY_NOBODY'"},
		{"contains", "CONTAINS 'ROLE_PARITY_READER'"},
	} {
		cases = append(cases, isolatedCase{
			id: "sl-claim-" + form.key, resourceType: "PARITY_SUITE_R9_SL_CLAIM_" + strings.ToUpper(strings.ReplaceAll(form.key, "-", "_")),
			condition: "subject.parityR9OneRole " + form.operator, pips: []any{round9OneRolePIP}, requests: claimRequests,
		})
	}
	s.runIsolatedCases(cases)
}

// What == and != answer over a resource attribute that is a plain JSON array.
// No golden records either operator over an array: j5-array-index compares one
// element, resource.list[0] == 'a', and is true. The agent's condition parser
// accepts both conditions.
//
// Each case is sent an array holding only the literal, an array holding it
// beside another value, an array without it, and a string, the control that
// the operator answers true where the attribute is a scalar.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9PlainArrayEqualityCases() {
	requests := func(scalar string) []isolatedRequest {
		return []isolatedRequest{
			{name: "array-of-only-v", resource: map[string]any{"id": "r9-array", "list": []string{"v"}}},
			{name: "array-of-v-and-w", resource: map[string]any{"id": "r9-array", "list": []string{"v", "w"}}},
			{name: "array-without-v", resource: map[string]any{"id": "r9-array", "list": []string{"w"}}},
			{name: "string-" + scalar, resource: map[string]any{"id": "r9-array", "list": scalar}},
		}
	}
	s.runIsolatedCases([]isolatedCase{
		{id: "pa-equals-over-an-array", resourceType: "PARITY_SUITE_R9_PA_EQUALS", condition: "resource.list == 'v'", requests: requests("v")},
		{id: "pa-not-equals-over-an-array", resourceType: "PARITY_SUITE_R9_PA_NOT_EQUALS", condition: "resource.list != 'v'", requests: requests("w")},
	})
}

// What IS NULL answers over the two forms the PAP accepts and the evaluator
// never matches: the bracket path resource['x'] and the literal null. Both
// answer false under every other operator recorded (j7-bracket-path, df1, df2), and IS NULL
// is the one operator that is true over an absent key (s6a), so a form read as
// an absent attribute is true here for every request. The agent's condition
// parser accepts both.
//
// Each case is sent a resource that holds x and one that does not.
// is-null-over-a-plain-path is the control: false and true.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9IsNullOverDeadFormsCases() {
	requests := []isolatedRequest{
		{name: "x-present", resource: map[string]any{"id": "r9-dead", "x": "v"}},
		{name: "x-absent", resource: map[string]any{"id": "r9-dead"}},
	}
	s.runIsolatedCases([]isolatedCase{
		{id: "dn-is-null-over-a-bracket-path", resourceType: "PARITY_SUITE_R9_DN_BRACKET", condition: "resource['x'] IS NULL", requests: requests},
		{id: "dn-is-null-over-the-null-literal", resourceType: "PARITY_SUITE_R9_DN_LITERAL", condition: "null IS NULL", requests: requests},
		{id: "dn-is-null-over-a-plain-path", resourceType: "PARITY_SUITE_R9_DN_PLAIN", condition: "resource.x IS NULL", requests: requests},
	})
}

// round9TokenDefaultPIP is a TOKEN PIP over a claim the reader's token does not
// carry, whose defaultValue holds a comma.
var round9TokenDefaultPIP = map[string]any{
	"name":         "subject.parityR9TokenDefault",
	"type":         "UUID",
	"pipType":      "TOKEN",
	"claim":        "parity_r9_no_such_claim",
	"defaultValue": "x, y",
	"cacheable":    false,
}

// Whether the defaultValue of a TOKEN PIP is split on commas, as a HEADER PIP's
// is (hl4 CONTAINS 'y' true, hl5 == 'x, y' false). p2 records a defaultValue
// without a comma. The agent's condition parser accepts both conditions.
// header-default-contains repeats hl4 in the same run, the control that the
// defaultValue form is accepted and applied.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound9TokenDefaultListCases() {
	requests := []isolatedRequest{{name: "claim-absent", resource: map[string]any{"id": "r9-tokdef"}}}
	s.runIsolatedCases([]isolatedCase{
		{id: "td-token-default-contains", resourceType: "PARITY_SUITE_R9_TD_CONTAINS", condition: "subject.parityR9TokenDefault CONTAINS 'y'",
			pips: []any{round9TokenDefaultPIP}, requests: requests},
		{id: "td-token-default-equals-the-string", resourceType: "PARITY_SUITE_R9_TD_EQUALS", condition: "subject.parityR9TokenDefault == 'x, y'",
			pips: []any{round9TokenDefaultPIP}, requests: requests},
		{id: "td-header-default-contains", resourceType: "PARITY_SUITE_R9_TD_HEADER", condition: "subject.parityHdrList CONTAINS 'y'",
			pips: []any{headerListPIP("x, y")}, requests: []isolatedRequest{{name: "no-header", resource: map[string]any{"id": "r9-tokdef"}}}},
	})
}
