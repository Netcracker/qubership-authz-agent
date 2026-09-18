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
)

func (s *ParitySuite) TestRow06CheckFilterV1GeneralScalarNumber() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/max-amount-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": 1000},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-scalar-number-substitution", "PARITY_SUITE_SCALAR_NUMBER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

// The template of TestRow06CheckFilterV1GeneralScalarNumber with the PIP
// answering the JSON string "1000" instead of the JSON number 1000. A ${...}
// placeholder is resolved by SpelContextStrLookup.lookup, which reads the
// provider AllOperandsVisitor builds — PipReturnType.MULTIPLE, so the value stays
// a Set and is rendered by collectionToDelimitedString(coll, ",", "\"", "\"").
// Nothing on that path casts, so the predicate comes out as the same quoted
// literal whichever JSON type the PIP returned, and this case records that.
//
// The pair is worth having because the other way a GENERAL PIP alias can be read
// — as a single operand inside a condition — resolves through
// PipReturnType.SINGLE and SinglePipDataConverter, whose unconditional checkcast
// to String turns a JSON number into a ClassCastException and a denied rule. Same
// PIP, same value, opposite tolerance: see the note in test/parity/README.md.
func (s *ParitySuite) TestRow06CheckFilterV1GeneralScalarNumberAsString() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/max-amount-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": "1000"},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-scalar-number-as-string-substitution", "PARITY_SUITE_SCALAR_NUMBER", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralScalarBoolean() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/archived-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": false},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-scalar-boolean-substitution", "PARITY_SUITE_SCALAR_BOOLEAN", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1TokenScalarIntoSQL() {
	s.runFilterV1Case("token-scalar-into-sql", "PARITY_SUITE_TOKEN_SQL", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1HeaderScalarIntoMongo() {
	s.runFilterV1Case(
		"header-scalar-into-mongodb",
		"PARITY_SUITE_HEADER_MONGO",
		"LIST",
		s.mustTokenBundle(UserProfileReader),
		PerCallOptions{CustomHeaders: map[string]string{"x-parity-pip-attribute": "parity-allow"}},
	)
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralArrayIntoSQL() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/allowed", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       []string{"row6-sql-1", "row6-sql-2"},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-array-into-sql", "PARITY_SUITE_ARRAY_SQL", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1MultiPipOneTemplate() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/max-amount-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": 1000},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("multi-pip-one-template", "PARITY_SUITE_MULTI_PIP", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}

func (s *ParitySuite) TestRow06CheckFilterV1GeneralScalarSpecialChars() {
	err := s.pipMock.PinRoute(context.Background(), "/api/v1/pip/tag-scalar", PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       map[string]any{"value": "red,blue;green('q')\"x\""},
	})
	s.Require().NoError(err)

	s.runFilterV1Case("general-scalar-special-chars", "PARITY_SUITE_TAG_SCALAR", "LIST", s.mustTokenBundle(UserProfileReader), PerCallOptions{})
}
