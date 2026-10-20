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

// TestLockdown checks on the deployed agent that the store, and the M2M token
// it holds under data.m2m, stay out of reach over HTTP: the internal port
// serves no route that reads or writes a store document, and the canonical
// route reads no query parameter, so ?explain=full gets the plain decision and
// no evaluation trace.
func (s *RuntimeSuite) TestLockdown() {
	s.Step("lockdown.m2m_read_absent.404", func() {
		url := s.cfg.OPADirectURL + "/v1/data/m2m"
		code, body, err := DoHTTP("GET", url, nil, nil)
		s.Require().NoError(err, "GET %s", url)
		s.Assert().Equal(404, code, "GET %s; body=%s", url, truncateBody(body))
		s.Assert().NotContains(string(body), "bearerToken", "GET %s returned the M2M token", url)
	})

	s.Step("lockdown.store_write_absent.404", func() {
		url := s.cfg.OPADirectURL + "/v1/data/lockdown-probe"
		code, body, err := DoHTTP("PUT", url, nil, []byte(`{"probe":true}`))
		s.Require().NoError(err, "PUT %s", url)
		s.Assert().Equal(404, code, "PUT %s; body=%s", url, truncateBody(body))
	})

	// The public gateway publishes this route, so this is the request an
	// anonymous caller on the internet can send. The two calls go out
	// back-to-back with the same body, and every byte but the per-call ids
	// has to match.
	s.Step("lockdown.authorize_explain_ignored.200", func() {
		token := "Bearer " + s.validAdminToken
		body := canonicalAuthorizeBody(token, token, map[string]interface{}{
			"resources": []map[string]interface{}{{"resourceType": "ORDER", "operation": "READ"}},
		})
		headers := s.headersWithRequestID(jsonHeader())
		url := s.cfg.BaseURL + "/access/v1/authorize"

		plainCode, plain, err := DoHTTP("POST", url, headers, body)
		s.Require().NoError(err, "POST %s", url)
		explainCode, explained, err := DoHTTP("POST", url+"?explain=full", headers, body)
		s.Require().NoError(err, "POST %s?explain=full", url)

		s.Require().Equal(200, plainCode, "POST %s; body=%s", url, truncateBody(plain))
		s.Assert().Equal(200, explainCode, "POST %s?explain=full; body=%s", url, truncateBody(explained))
		s.Assert().Equal(maskDecisionID(plain), maskDecisionID(explained),
			"POST %s?explain=full must answer the plain decision", url)
	})
}
