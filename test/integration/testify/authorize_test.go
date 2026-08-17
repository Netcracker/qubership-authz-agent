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

package runtimetest

import "strings"

// rsqlPredicateFrom extracts the aggregated predicate string for the "rsql"
// predicateType from a canonical authorize result entry (ADR-0029).
func rsqlPredicateFrom(result map[string]interface{}) string {
	preds, ok := result["predicates"].([]interface{})
	if !ok {
		return ""
	}
	for _, p := range preds {
		entry, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if entry["predicateType"] == "rsql" {
			pred, _ := entry["predicate"].(string)
			return pred
		}
	}
	return ""
}

// All canonical /access/v1/authorize bodies in this file are wrapped in the OPA
// Data API envelope and carry the four (R) fields via the postAuthorize helper
// (suite_test.go). Per ADR-0062 the admission token rides in body.authorizationToken
// — the HTTP Authorization header is NOT set for canonical authorize calls.
func (s *RuntimeSuite) TestAuthorize() {
	s.Step("authorize.order_read.rls_true.deny", func() {
		token := "Bearer " + s.validOrderReaderToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ", "resource": map[string]interface{}{"id": "order-1", "ownerId": "order-reader-1"}},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		s.Assert().Equal(false, j["rlsIgnored"])
		results := j["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(false, r0["isAllowed"])
		s.Assert().Equal("ORDER", r0["resourceType"])
		s.Assert().Equal("READ", r0["operation"])
	})

	s.Step("authorize.order_read.response_structure", func() {
		token := "Bearer " + s.validAdminToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, isBool := j["rlsIgnored"].(bool)
		s.Assert().True(isBool, "rlsIgnored must be boolean")
		// ADR-0063: pipTrace is retired from the canonical response on both
		// transports — PIP context now lives only in the decision log via
		// nd_builtin_cache, never in the client-facing body.
		_, hasPIPTrace := j["pipTrace"]
		s.Assert().False(hasPIPTrace, "canonical response must not surface pipTrace (ADR-0063)")
		results, isArr := j["results"].([]interface{})
		s.Assert().True(isArr, "results must be array")
		r0 := results[0].(map[string]interface{})
		_, isAllowedBool := r0["isAllowed"].(bool)
		s.Assert().True(isAllowedBool, "isAllowed must be bool")
		s.Assert().Equal("ORDER", r0["resourceType"])
	})

	s.Step("authorize.public_doc_read.rls_default.allow", func() {
		token := "Bearer " + s.validAdminToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "PUBLIC_DOC", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		s.Assert().Equal(false, j["rlsIgnored"])
		results := j["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(true, r0["isAllowed"])
		pred := rsqlPredicateFrom(r0)
		s.Assert().True(strings.HasPrefix(pred, "subjectId=="),
			"predicate must start with subjectId==, got: %s", pred)
		s.Assert().NotContains(pred, "${subject.",
			"predicate must not contain unresolved ${subject.*, got: %s", pred)
	})

	s.Step("authorize.multi_resource.order_preserved", func() {
		token := "Bearer " + s.validOrderReaderToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
				{"resourceType": "ATTACHMENT", "operation": "READ"},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		results := j["results"].([]interface{})
		s.Require().Len(results, 2)
		s.Assert().Equal("ORDER", results[0].(map[string]interface{})["resourceType"])
		s.Assert().Equal("ATTACHMENT", results[1].(map[string]interface{})["resourceType"])
		for _, r := range results {
			_, ok := r.(map[string]interface{})["isAllowed"].(bool)
			s.Assert().True(ok, "each result must have a bool isAllowed")
		}
	})

	s.Step("authorize.no_token.401", func() {
		// Empty body.authorizationToken → admission failure → result.authError carrying
		// status=401. ADR-0062: the canonical envelope surfaces OPA's data API verbatim
		// on both transports (HTTP 200 with embedded authError), so the wire status no
		// longer carries the auth verdict — `.authError.status` does.
		code, b := s.postAuthorize("", "", map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
		s.Assert().NotEmpty(authErr["reason"], "canonical authError must include reason")
	})

	s.Step("authorize.expired_token.401", func() {
		token := "Bearer " + s.expiredOrderReaderToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
		s.Assert().NotEmpty(authErr["reason"], "canonical authError must include reason")
	})

	s.Step("authorize.invalid_token.401", func() {
		code, b := s.postAuthorize("Bearer invalid.jwt.token", "Bearer invalid.jwt.token", map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
		s.Assert().NotEmpty(authErr["reason"], "canonical authError must include reason")
	})

	s.Step("authorize.naked_authorization_token.401", func() {
		// admission token without "Bearer " prefix → admission failure → result.authError.
		code, b := s.postAuthorize(s.validAdminToken, "Bearer "+s.validAdminToken, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
		s.Assert().Equal("Authorization scheme must be Bearer", authErr["reason"])
	})

	s.Step("authorize.naked_subject_token.deny", func() {
		token := "Bearer " + s.validAdminToken
		// subject without "Bearer " prefix → per-resource DENY with reason.
		code, b := s.postAuthorize(token, s.validAdminToken, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		results := j["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(false, r0["isAllowed"])
		s.Assert().Equal("Authorization scheme must be Bearer", r0["reason"])
	})

	s.Step("authorize.missing_subject.401", func() {
		// Per ADR-0062 admission gate runs before subject validation: with no
		// admission token in body the request surfaces authError.status=401
		// regardless of subject (wire status remains 200 — ADR-0062).
		code, b := s.postAuthorize("", "", map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "ORDER", "operation": "READ"},
			},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
	})

	s.Step("authorize.empty_body.401", func() {
		// Schema-minimal envelope: every required input field present but
		// zero-valued. Equivalent semantically to the pre-ADR-0062 "empty body"
		// scenario — empty admission token + no resources → admission gate
		// fires, authError.status=401 inside the envelope (HTTP 200, ADR-0062).
		code, b := s.postAuthorize("", "", map[string]interface{}{
			"resources": []map[string]interface{}{},
		})
		s.Require().Equal(200, code)
		authErr := authErrorFrom(s.T(), b)
		s.Assert().EqualValues(401, authErr["status"])
	})

	s.Step("authorize.predicate_subject_attr_substituted", func() {
		token := "Bearer " + s.validAdminToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "PUBLIC_DOC", "operation": "READ"},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code, "body: %s", string(b))
		results := jsonObj(b)["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(true, r0["isAllowed"])
		pred := rsqlPredicateFrom(r0)
		s.Assert().True(strings.HasPrefix(pred, "subjectId=="),
			"predicate must start with subjectId==, got: %s", pred)
		s.Assert().NotContains(pred, "${subject.",
			"${subject.id} must be substituted, got: %s", pred)
		s.Assert().True(len(pred) > len("subjectId=="),
			"substituted value must not be empty, got: %s", pred)
	})

	s.Step("authorize.multi_frag.rls_or_aggregation", func() {
		token := "Bearer " + s.validAdminToken
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "MULTI_FRAG_ITEM", "operation": "READ"},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal(false, j["rlsIgnored"])
		results := j["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(true, r0["isAllowed"])
		pred := rsqlPredicateFrom(r0)
		// D-AF-S (2026-04-15, supersedes ADR-0025 parenthesized OR):
		// two-fragment RSQL aggregation is flat comma-joined,
		// matching legacy `access-control`'s aggregator output.
		s.Assert().Equal("dept==engineering,dept==management", pred,
			"multi-fragment rsql must be flat comma-joined per D-AF-S, got: %s", pred)
	})

	s.Step("authorize.predicate_pip_value_substituted", func() {
		// D-AF-W item 5d (2026-04-17): pin the pip-stub's
		// `/api/v1/pip/allowed` response explicitly. The step
		// previously relied on the shared container's default
		// fixture (`["C1","C2","C3"]`), but any preceding testify
		// step that configures the same path via
		// `PUT /pip-stub/configure` overrides the default until
		// the container restarts. Every step that asserts a
		// pip-resolved predicate now pins its own values.
		pinPayload := `[{"path":"/api/v1/pip/allowed","responses":[{"statusCode":200,"body":["C1","C2","C3"]}]}]`
		resetCode, _ := s.doHTTPDirect(
			"PUT",
			s.cfg.PIPStubURL+"/pip-stub/configure",
			map[string]string{"Content-Type": "application/json"},
			[]byte(pinPayload),
		)
		s.Require().Equal(200, resetCode)

		token := "Bearer " + s.validAdminToken
		// D-AF-AB (2026-04-20): the CUSTOMER READ policy gained a
		// `condition: "resource.customerId IN subject.allowedCustomers"`
		// AST clause under the S1 runtime-testify fixture patch so the
		// bulk check-resource path can filter per-resource. The
		// per-resource condition evaluates against the resource body,
		// so the preview-style authorize probe must now carry a
		// `customerId` that matches the pinned allowlist
		// (`["C1","C2","C3"]`) for the policy to reach ALLOW and emit
		// the rsql predicate. The assertion shape (predicate string)
		// is unchanged.
		code, b := s.postAuthorize(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{
				{"resourceType": "CUSTOMER", "operation": "READ", "resource": map[string]interface{}{"customerId": "C1"}},
			},
			"ignoreRls": false,
		})
		s.Require().Equal(200, code, "body: %s", string(b))
		results := jsonObj(b)["results"].([]interface{})
		r0 := results[0].(map[string]interface{})
		s.Assert().Equal(true, r0["isAllowed"])
		pred := rsqlPredicateFrom(r0)
		// D-AF-R (OQ-AF-6, 2026-04-15): PIP-resolved array elements
		// are JSON-quoted and comma-space-joined per the legacy
		// parity contract (`check-filter-v1/general-pip-list.json`).
		s.Assert().Equal(`customerId=in=("C1", "C2", "C3")`, pred,
			"PIP value must be substituted into predicate, got: %s", pred)
	})
}
