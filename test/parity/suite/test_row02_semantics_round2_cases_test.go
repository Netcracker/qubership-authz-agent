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

	"authz-agent/test/parity/suite/model"
)

// The second round of semantics cases looks for the edges of what the first round
// found: where a null value stops being a value, how operators coerce types, and
// what a request resource that is not an object does. The policies share the
// seeded pack (testdata/fixtures/policies/suite/semantics-round2.json), so each
// uses an operator form the PAP accepted in an existing golden: ==, != and IN
// against a string literal, == true, NOT IN, NOT CONTAINS, > against a number,
// IS NULL, and IS EMPTY. Forms and declarations the PAP may refuse are in
// test_isolated_policy_cases_test.go, where a refusal cannot fail the seed.

func (s *ParitySuite) TestRow02CheckResourceV1NullValueUnderOperators() {
	s.runSemanticsCases([]semanticsCase{
		{"n1-not-in-attribute-null", "PARITY_SUITE_SEM2_N1", map[string]any{"id": "sem2-n1", "x": nil}},
		{"n2-not-contains-attribute-null", "PARITY_SUITE_SEM2_N2", map[string]any{"id": "sem2-n2", "tags": nil}},
		{"n3-greater-than-null-or-true", "PARITY_SUITE_SEM2_N3", map[string]any{"id": "sem2-n3", "n": nil, "a": "y"}},
		{"n4-is-empty-attribute-null", "PARITY_SUITE_SEM2_N4", map[string]any{"id": "sem2-n4", "tags": nil}},
		{"n4-control-is-empty-empty-collection", "PARITY_SUITE_SEM2_N4", map[string]any{"id": "sem2-n4c", "tags": []string{}}},
	})
}

func (s *ParitySuite) TestRow02CheckResourceV1ValueCoercion() {
	s.runSemanticsCases([]semanticsCase{
		{"c3-greater-than-string-number", "PARITY_SUITE_SEM2_C3", map[string]any{"id": "sem2-c3", "n": "10"}},
		{"c3-control-greater-than-number", "PARITY_SUITE_SEM2_C3", map[string]any{"id": "sem2-c3c", "n": 10}},
		{"c4-boolean-equals-string", "PARITY_SUITE_SEM2_C4", map[string]any{"id": "sem2-c4", "b": "true"}},
		{"c5-string-equals-other-case", "PARITY_SUITE_SEM2_C5", map[string]any{"id": "sem2-c5", "x": "V"}},
		{"c6-string-equals-leading-space", "PARITY_SUITE_SEM2_C5", map[string]any{"id": "sem2-c6", "x": " v"}},
		{"c8-is-empty-empty-string", "PARITY_SUITE_SEM2_C8", map[string]any{"id": "sem2-c8", "x": ""}},
		{"c8-control-is-empty-non-empty-string", "PARITY_SUITE_SEM2_C8", map[string]any{"id": "sem2-c8c", "x": "abc"}},
		{"c9-is-null-empty-string", "PARITY_SUITE_SEM2_C9", map[string]any{"id": "sem2-c9", "x": ""}},
		{"l6-is-empty-empty-object", "PARITY_SUITE_SEM2_L6", map[string]any{"id": "sem2-l6", "obj": map[string]any{}}},
		{"l7-collection-in-list", "PARITY_SUITE_SEM2_L7", map[string]any{"id": "sem2-l7", "tags": []string{"red"}}},
	})
}

// K1 and K2 send the resource type and the operation of the round 1 policy
// PARITY_SUITE_SEM_S1 in lowercase, with a resource that satisfies its condition.
// Access-control may refuse such a request, so the status is recorded too.
func (s *ParitySuite) TestRow02CheckResourceV1RequestKeyCase() {
	cases := []struct{ subCase, operation, resourceType string }{
		{"k1-resource-type-lowercase", "READ", "parity_suite_sem_s1"},
		{"k2-operation-lowercase", "read", "PARITY_SUITE_SEM_S1"},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				"semantics/"+tc.subCase,
				model.CheckAccessRequest{Operation: tc.operation, Type: tc.resourceType, Resource: map[string]any{"id": "sem2-" + tc.subCase, "x": "v"}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

// PARITY_SUITE_SEM2_R1 holds resource.x IS NULL, which a resource object without x
// satisfies. Access-control may refuse a request whose resource is not an object,
// so the status is recorded too.
func (s *ParitySuite) TestRow02CheckResourceV1ResourceNotAnObject() {
	cases := []struct {
		subCase  string
		resource any
	}{
		{"r1-resource-absent", nil},
		{"r2-resource-string", "abc"},
		{"r3-resource-array", []string{"a"}},
	}
	for _, tc := range cases {
		s.Run(tc.subCase, func() {
			s.runPendingCheckResourceV1OutcomeCase(
				"semantics/"+tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_SEM2_R1", Resource: tc.resource},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1GeneralPIPNotFound() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/sem-404", PipStubResponse{
		StatusCode: http.StatusNotFound,
		Body:       map[string]any{"error": "parity semantics case"},
	})
	s.Require().NoError(err)

	s.runSemanticsCases([]semanticsCase{
		{"p6-not-found-pip-neq", "PARITY_SUITE_SEM2_P6", map[string]any{"id": "sem2-p6"}},
	})
}

func (s *ParitySuite) TestRow02CheckResourceV1GeneralPIPNullBody() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/sem-null-body", PipStubResponse{
		StatusCode: http.StatusOK,
		BodyRaw:    "null",
	})
	s.Require().NoError(err)

	s.runSemanticsCases([]semanticsCase{
		{"p7-null-body-pip-neq", "PARITY_SUITE_SEM2_P7", map[string]any{"id": "sem2-p7"}},
	})
}
