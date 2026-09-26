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
	"encoding/json"
	"errors"
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

// emptyPolicySetsOnCleanup registers a cleanup that replaces the regular sets
// uploaded under each of externalIDs in the tenant of cfg with an empty list. A
// regular set that names a PIP declaration no longer in the isolated domain
// makes access-control refuse every check request on the stand with 400, so a
// test that uploads sets and empties the domain when it ends has to empty the
// sets first; cleanups run last registered first, so this one is registered
// after the domain's.
func (s *ParitySuite) emptyPolicySetsOnCleanup(cfg Config, externalIDs ...string) {
	s.T().Helper()
	ctx := context.Background()
	m2m := s.mustM2MToken()
	s.T().Cleanup(func() {
		for _, externalID := range externalIDs {
			status, _, err := HelperPutPolicySets(ctx, cfg, m2m, externalID, []any{})
			if err != nil {
				s.T().Logf("empty the policy sets of %s: %v", externalID, err)
				continue
			}
			if status < http.StatusOK || status >= http.StatusMultipleChoices {
				s.T().Logf("empty the policy sets of %s: status %d", externalID, status)
			}
		}
	})
}

func (s *ParitySuite) requireGolden(id ParityEndpointID, subCase string, actual any) {
	s.T().Helper()
	if err := s.comparator.Compare(id, subCase, actual); err != nil {
		s.T().Errorf("%v", err)
	}
}

// requirePendingGolden is requireGolden for a case written before access-control
// answered it. With no golden recorded the case skips and prints the answer of the
// service under test, which is access-control when the golden is being captured;
// once the golden is committed it compares like any other case.
func (s *ParitySuite) requirePendingGolden(id ParityEndpointID, subCase string, actual any) {
	s.T().Helper()
	err := s.comparator.Compare(id, subCase, actual)
	if errors.Is(err, ErrGoldenNotRecorded) {
		answer, _ := json.Marshal(actual)
		s.T().Skipf("golden %s/%s is not recorded yet; the %s profile answered %s", Meta(id).GoldenDir, subCase, s.cfg.Profile, answer)
	}
	if err != nil {
		s.T().Errorf("%v", err)
	}
}

func (s *ParitySuite) runPendingCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decision)
}

// runRepeatedPendingCheckResourceV1Case sends the same request calls times. The
// answers have to agree with each other before the first one is compared with the
// golden, so an order-dependent answer shows up even while recording.
func (s *ParitySuite) runRepeatedPendingCheckResourceV1Case(subCase string, body model.CheckAccessRequest, tokens TokenBundle, calls int) {
	s.T().Helper()

	decisions := make([]bool, 0, calls)
	distinct := map[bool]struct{}{}
	for range calls {
		status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, PerCallOptions{})
		s.Require().NoError(err)
		s.Require().Equal(http.StatusOK, status)
		decisions = append(decisions, decision)
		distinct[decision] = struct{}{}
	}
	s.Require().Len(distinct, 1, "decisions over %d identical calls: %v", calls, decisions)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1, subCase, &decisions[0])
}

// runPendingCheckResourceV1OutcomeCase records the HTTP status together with the
// decision, so a request access-control refuses is recorded rather than failed.
func (s *ParitySuite) runPendingCheckResourceV1OutcomeCase(subCase string, body model.CheckAccessRequest, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decision, _, err := HelperCheckResourceV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.requirePendingGolden(PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, subCase, &model.CheckResourceOutcome{Status: status, Decision: decision})
}

// runPendingFilterV1OutcomeCase is runPendingCheckResourceV1OutcomeCase for
// check/filter.
func (s *ParitySuite) runPendingFilterV1OutcomeCase(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.requirePendingGolden(PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, subCase, &model.FilterOutcome{Status: status, Result: decoded})
}

func (s *ParitySuite) runPendingCheckResourceBulkV1Case(subCase string, body []model.CheckAccessRequestWithID, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperCheckResourcesV1(context.Background(), s.cfg, body, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_3_CHECK_RESOURCE_BULK_V1, subCase, &decoded)
}

func (s *ParitySuite) runPendingFilterV1Case(subCase, resourceType, operation string, tokens TokenBundle, opts PerCallOptions) {
	s.T().Helper()

	status, decoded, _, err := HelperFilterV1(context.Background(), s.cfg, resourceType, operation, tokens, opts)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)
	s.requirePendingGolden(PSUITE_ROW_6_CHECK_FILTER_V1, subCase, &decoded)
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

// sendRegularRequest sends req against its own type, or resourceType when it
// names none, with the tokens requestTokens gives it, and returns the outcome
// with the endpoint its golden is filed under, as runRegularCases records it.
func (s *ParitySuite) sendRegularRequest(resourceType string, req isolatedRequest) (ParityEndpointID, any) {
	s.T().Helper()
	ctx := context.Background()
	opts := req.callOptions()
	if req.filter {
		status, decoded, _, err := HelperFilterV1(ctx, s.cfg, valueOr(req.typ, resourceType), req.filterOperation(), s.requestTokens(req), opts)
		s.Require().NoError(err)
		return PSUITE_ROW_6_CHECK_FILTER_V1_OUTCOME, &model.FilterOutcome{Status: status, Result: decoded}
	}
	status, decision, _, err := HelperCheckResourceV1(ctx, s.cfg,
		model.CheckAccessRequest{Operation: valueOr(req.operation, "READ"), Type: valueOr(req.typ, resourceType), Resource: req.resource},
		s.requestTokens(req), opts)
	s.Require().NoError(err)
	return PSUITE_ROW_2_CHECK_RESOURCE_V1_OUTCOME, &model.CheckResourceOutcome{Status: status, Decision: decision}
}

// runPIPCallRequest clears the pip-mock call log, sends req against
// resourceType, and records what the route req.pipCalls received as the
// pip-call golden subCase beside the request's own golden. The call log is read
// before either golden is compared, since a golden not yet recorded skips the
// rest of the subtest.
func (s *ParitySuite) runPIPCallRequest(subCase, resourceType string, req isolatedRequest) {
	s.T().Helper()
	s.Require().NoError(s.pipMock.ResetCalls(context.Background()))
	id, outcome := s.sendRegularRequest(resourceType, req)
	calls := s.pipCallOutcome(req.pipCalls)
	s.Run("pip-calls", func() {
		s.requirePendingGolden(PSUITE_PIP_CALL, subCase, calls)
	})
	s.requirePendingGolden(id, subCase, outcome)
}

// pipCalls counts the calls pip-mock received on route since its call log was
// last reset.
func (s *ParitySuite) pipCalls(route string) int {
	s.T().Helper()
	calls, err := s.pipMock.GetCalls(context.Background())
	s.Require().NoError(err, "read the pip-mock call log for %s", route)
	read := 0
	for _, call := range calls {
		if call.Path == route {
			read++
		}
	}
	return read
}

// pipCallOutcome reads the pip-mock call log for route into the golden shape
// PipCallOutcome.
func (s *ParitySuite) pipCallOutcome(route string) *model.PipCallOutcome {
	s.T().Helper()
	calls, err := s.pipMock.GetCalls(context.Background())
	s.Require().NoError(err, "read the pip-mock call log for %s", route)
	return s.pipCallOutcomeOf(calls, route)
}

// pipCallOutcomeOf is pipCallOutcome over a call log already read.
func (s *ParitySuite) pipCallOutcomeOf(calls []PipStubCall, route string) *model.PipCallOutcome {
	s.T().Helper()
	outcome := &model.PipCallOutcome{}
	for _, call := range calls {
		if call.Path != route {
			continue
		}
		outcome.Calls++
		if outcome.Calls > 1 {
			continue
		}
		body, isObject := call.Body.(map[string]any)
		if attributes, ok := body["requestAttributes"]; isObject && ok {
			outcome.RequestAttributes = attributes
			continue
		}
		raw := call.BodyRaw
		if raw == "" && call.Body != nil {
			encoded, err := json.Marshal(call.Body)
			s.Require().NoError(err)
			raw = string(encoded)
		}
		outcome.Body = raw
	}
	return outcome
}
