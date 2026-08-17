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
	"authz-agent/test/parity/suite/model"
)

func (s *ParitySuite) TestRow02CheckResourceV1EntContains() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1"}},
	})

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "allow", subCase: "ent-contains/allow", resourceID: "id-1"},
		{name: "deny", subCase: "ent-contains/deny", resourceID: "id-2"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_CONTAINS", Resource: map[string]any{"id": tc.resourceID}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntInRhs() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1"}},
	})

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "allow", subCase: "ent-in-rhs/allow", resourceID: "id-1"},
		{name: "deny", subCase: "ent-in-rhs/deny", resourceID: "id-2"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_IN", Resource: map[string]any{"id": tc.resourceID}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntMultiAs() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1"}, "Accountant": {"id-2"}},
	})

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "owner", subCase: "ent-multi-as/owner", resourceID: "id-1"},
		{name: "accountant", subCase: "ent-multi-as/accountant", resourceID: "id-2"},
		{name: "deny", subCase: "ent-multi-as/deny", resourceID: "id-3"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_MULTI", Resource: map[string]any{"id": tc.resourceID}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntContainsAny() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1", "id-2"}},
	})

	cases := []struct {
		name       string
		subCase    string
		relatedIDs []string
	}{
		{name: "allow", subCase: "ent-contains-any/allow", relatedIDs: []string{"id-1", "id-99"}},
		{name: "deny", subCase: "ent-contains-any/deny", relatedIDs: []string{"id-99"}},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_ANY", Resource: map[string]any{"id": "row2-ent-any-" + tc.name, "relatedIds": tc.relatedIDs}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntIsEmpty() {
	cases := []struct {
		name    string
		subCase string
		refs    map[string]map[string][]string
	}{
		{name: "empty", subCase: "ent-is-empty/empty", refs: map[string]map[string][]string{"PARITY_CONTRACT": {"Owner": {}}}},
		{name: "non-empty", subCase: "ent-is-empty/non-empty", refs: map[string]map[string][]string{"PARITY_CONTRACT": {"Owner": {"id-1"}}}},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.pinEntitlementsV3(parityReaderSubjectID, tc.refs)
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_EMPTY", Resource: map[string]any{"id": "row2-ent-empty-" + tc.name}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntNotContains() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1"}},
	})

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "allow-negated", subCase: "ent-not-contains/allow-negated", resourceID: "id-2"},
		{name: "deny-negated", subCase: "ent-not-contains/deny-negated", resourceID: "id-1"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_NOT", Resource: map[string]any{"id": tc.resourceID}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntMultiResourceType() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{
		"PARITY_CONTRACT": {"Owner": {"id-1"}},
		"PARITY_ACCOUNT":  {"Owner": {"id-2"}},
	})

	cases := []struct {
		name       string
		subCase    string
		resourceID string
	}{
		{name: "contract-hit", subCase: "ent-multi-resource-type/contract-hit", resourceID: "id-1"},
		{name: "other-type-miss", subCase: "ent-multi-resource-type/other-type-miss", resourceID: "id-2"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: "PARITY_SUITE_ENT_CONTAINS", Resource: map[string]any{"id": tc.resourceID}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}

func (s *ParitySuite) TestRow02CheckResourceV1EntEmptyUser() {
	s.pinEntitlementsV3(parityReaderSubjectID, map[string]map[string][]string{})

	cases := []struct {
		name     string
		subCase  string
		testType string
	}{
		{name: "contains-false", subCase: "ent-empty-user/contains-false", testType: "PARITY_SUITE_ENT_CONTAINS"},
		{name: "is-empty-true", subCase: "ent-empty-user/is-empty-true", testType: "PARITY_SUITE_ENT_EMPTY"},
	}

	for _, tc := range cases {
		tc := tc
		s.Run(tc.name, func() {
			s.runCheckResourceV1Case(
				tc.subCase,
				model.CheckAccessRequest{Operation: "READ", Type: tc.testType, Resource: map[string]any{"id": "id-any"}},
				s.mustTokenBundle(UserProfileReader),
				PerCallOptions{},
			)
		})
	}
}
