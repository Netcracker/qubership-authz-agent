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
	"sort"

	"authz-agent/test/parity/suite/model"
)

func stringPtr(v string) *string { return &v }

func (s *ParitySuite) mustM2MToken() string {
	s.T().Helper()
	token, err := s.tokens.M2MToken()
	s.Require().NoError(err)
	return token
}

func (s *ParitySuite) mustEndUserToken(profile UserProfile) string {
	s.T().Helper()
	token, err := s.tokens.EndUserToken(profile)
	s.Require().NoError(err)
	return token
}

func (s *ParitySuite) mustTokenBundle(profile UserProfile) TokenBundle {
	s.T().Helper()
	return TokenBundle{
		M2M:     s.mustM2MToken(),
		EndUser: s.mustEndUserToken(profile),
	}
}

func (s *ParitySuite) mustAnonymousTokenBundle() TokenBundle {
	s.T().Helper()
	return TokenBundle{
		M2M:       s.mustM2MToken(),
		Anonymous: true,
	}
}

func (s *ParitySuite) requireGolden(id ParityEndpointID, subCase string, actual any) {
	s.T().Helper()
	if err := s.comparator.Compare(id, subCase, actual); err != nil {
		s.T().Errorf("%v", err)
	}
}

func (s *ParitySuite) runCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decision)
}

func (s *ParitySuite) runCheckResourceV2Case(subCase string, body model.CheckResourceRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourceV2(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_7_CHECK_RESOURCE_V2, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkV1Case(subCase string, body []model.CheckAccessRequestWithID, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkOpsV1Case(subCase string, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesByOperationsV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_4_CHECK_RESOURCE_BULK_OPERATIONS_V1, subCase, &decoded)
}

func (s *ParitySuite) runPreviewBulkOpsV1Case(subCase string, body []model.CheckAccessBulkOperationsRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperPreviewCheckResourcesByOperationsV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_5_PREVIEW_BULK_OPERATIONS_V1, subCase, &decoded)
}

func (s *ParitySuite) runFilterV1Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_6_CHECK_FILTER_V1, subCase, &decoded)
}

func (s *ParitySuite) runCheckResourceBulkOpsV2Case(subCase string, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV2(context.Background(), s.cfg, body, tokens, opts, v2Flags{})
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_8_CHECK_RESOURCE_BULK_OPERATIONS_V2, subCase, &decoded)
}

func (s *ParitySuite) runPreviewBulkOpsV2Case(subCase string, body model.CheckResourcesRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperPreviewCheckResourcesV2(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_9_PREVIEW_BULK_OPERATIONS_V2, subCase, &decoded)
}

func (s *ParitySuite) runFilterV2Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV2(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requireGolden(PSUITE_ROW_10_CHECK_FILTER_V2, subCase, &decoded)
}

func (s *ParitySuite) pinEntitlementsV3(userID string, refs map[string]map[string][]string) {
	s.T().Helper()

	ctx := context.Background()
	err := s.eaMock.PinRoute(ctx, "/api-version", PipStubResponse{
		StatusCode: http.StatusOK,
		Body: model.ApiVersionResponse{
			Specs: []model.ApiVersionSpec{{
				SpecRootUrl:     "/api",
				Major:           3,
				Minor:           0,
				SupportedMajors: []int{1, 2, 3},
			}},
		},
	})
	s.Require().NoError(err)

	payload := buildDirectEntitlementsResponse(refs)
	err = s.eaMock.PinEntitlementsV3ForUser(ctx, userID, PipStubResponse{
		StatusCode: http.StatusOK,
		Body:       payload,
	})
	s.Require().NoError(err)
}

func buildDirectEntitlementsResponse(refs map[string]map[string][]string) model.GetDirectUserEntitlementsResponse {
	resourceTypes := make([]string, 0, len(refs))
	for resourceType := range refs {
		resourceTypes = append(resourceTypes, resourceType)
	}
	sort.Strings(resourceTypes)

	entitlements := make([]model.Entitlement, 0, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		names := make([]string, 0, len(refs[resourceType]))
		for name := range refs[resourceType] {
			names = append(names, name)
		}
		sort.Strings(names)

		references := make([]model.EntitlementReference, 0, len(names))
		for _, name := range names {
			ids := append([]string(nil), refs[resourceType][name]...)
			sort.Strings(ids)

			targets := make([]model.EntitlementTarget, 0, len(ids))
			for _, id := range ids {
				targets = append(targets, model.EntitlementTarget{ResourceID: id})
			}
			references = append(references, model.EntitlementReference{
				Name:      name,
				Resources: targets,
			})
		}
		entitlements = append(entitlements, model.Entitlement{
			ResourceType: resourceType,
			References:   references,
		})
	}

	return model.GetDirectUserEntitlementsResponse{
		Entitlements:          entitlements,
		Definitions:           []model.Definition{},
		DefinitionUpdatedWhen: "",
	}
}
