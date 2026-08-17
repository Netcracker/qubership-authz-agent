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

func (s *RuntimeSuite) TestCheckFilter() {
	s.Step("check_filter.calculation_result_present", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.unknown_type.deny", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		s.Assert().Equal("DENY", jsonObj(b)["calculationResult"])
	})

	// Per the parity goldens under
	// tests/parity/suite/testdata/golden/check-filter-v1/*.json pin the
	// legacy wire shape — `customFilterCondition` is JSON `null` on every
	// simplified-policy path (legacy only emits a string there for regular
	// full-policy rules, which row 4 / ADR-0051 permanently defers). The
	// other five fields stay strings; only `customFilterCondition` is
	// allowed to be null.
	s.Step("check_filter.deny_all_fields", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		for _, field := range []string{
			"calculationResult", "filterCondition",
			"mongodbFilterCondition", "rsqlFilterCondition",
			"sqlFilterCondition",
		} {
			_, ok := j[field].(string)
			s.Assert().True(ok, "field %s must be a string", field)
		}
		// customFilterCondition is JSON null on the simplified-policy path.
		s.Assert().Nil(j["customFilterCondition"],
			"customFilterCondition must be JSON null on simplified-policy deny path")
	})

	s.Step("check_filter.known_resource.not_null", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ATTACHMENT&operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.missing_operation", func() {
		h := incomingTokenHeader(s.validOrderReaderToken)
		code, b := s.post("/access/v1/check/filter?resourceType=ATTACHMENT&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		j := jsonObj(b)
		_, ok := j["calculationResult"].(string)
		s.Assert().True(ok, "calculationResult must be a string")
	})

	s.Step("check_filter.tenant_id_ignored", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=NONEXISTENT&operation=READ&tenant_id=completely-different-tenant", h, map[string]interface{}{})
		s.Require().Equal(200, code)
		s.Assert().Equal("DENY", jsonObj(b)["calculationResult"])
	})

	s.Step("check_filter.no_token.401", func() {
		code, b := s.post("/access/v1/check/filter?resourceType=ORDER&operation=READ&tenant_id=default", jsonHeader(), map[string]interface{}{})
		s.Require().Equal(401, code)
		s.Assert().NotEmpty(jsonObj(b)["message"], "legacy 401 must include message")
	})

	s.Step("check_filter.missing_resource_type.400", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.postRaw("/access/v1/check/filter?operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(400, code)
		s.Assert().Equal("bad request", jsonObj(b)["message"])
	})

	// `filterCondition` is always empty on the
	// simplified-policy path (legacy's generic `predicate` template
	// does not exist in simplified format). Decision D-AF-S
	// (2026-04-15, supersedes ADR-0025): two-fragment RSQL
	// aggregation is flat comma-joined — legacy does not wrap each
	// item in parentheses.
	s.Step("check_filter.multi_frag.rsql_or_aggregation", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filter?resourceType=MULTI_FRAG_ITEM&operation=READ", h, map[string]interface{}{})
		s.Require().Equal(200, code, "body: %s", string(b))
		j := jsonObj(b)
		s.Assert().Equal("USE_FILTER_CONDITION", j["calculationResult"])
		rsql, _ := j["rsqlFilterCondition"].(string)
		s.Assert().Equal("dept==engineering,dept==management", rsql,
			"rsqlFilterCondition must be flat comma-joined per D-AF-S, got: %s", rsql)
		filter, _ := j["filterCondition"].(string)
		s.Assert().Equal("", filter,
			"filterCondition is always empty on the simplified-policy path per the parity goldens, got: %s", filter)
	})

	s.Step("check_filter.wrong_address.404", func() {
		h := incomingTokenHeader(s.validAdminToken)
		code, b := s.post("/access/v1/check/filte?resourceType=ORDER&operation=READ&tenant_id=default", h, map[string]interface{}{})
		s.Require().Equal(404, code)
		s.Assert().Equal("not found", jsonObj(b)["message"])
	})
}
