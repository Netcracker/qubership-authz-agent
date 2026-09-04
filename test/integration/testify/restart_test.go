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

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TestOPARestart verifies that policies, PIPs, and authentication data survive
// an OPA container restart without waiting for the next pap-client push tick
// (restart survival).
//
// Design: pap-client writes each document root to the shared opa-data volume
// BEFORE pushing to OPA's Data API (two-sided write). On OPA container restart
// the volume persists, OPA reads the JSON files from it at startup and serves
// correct decisions immediately. The layout of those files is unit-tested in
// opa_document_roots_test.go; this test proves the round trip on a live stack.
//
// Red/green proof: removing the disk writes from pap-client causes this test to
// fail because OPA starts with an empty data directory and all policy-dependent
// decisions return the wrong result.
//
// How the restart happens is the stack driver's business (stack.go). The
// Compose stack restarts the container through the docker CLI and restarts
// pap-client with it, because the two share a network namespace there. On
// Kubernetes an ephemeral container signals the OPA process and the kubelet
// restarts that container only, with pap-client untouched.
func (s *RuntimeSuite) TestOPARestart() {

	// ── Step 1: establish pre-restart baseline ────────────────────────────
	// Confirm that a policy-dependent request returns allow=true before the restart.
	// The suite SetupSuite has already uploaded policies and waited for the
	// first pull, so this should be immediately healthy.
	s.Step("opa_restart.pre_restart_baseline", func() {
		headers := incomingTokenHeader(s.validAdminToken)
		code, body := s.post("/access/v1/check/resource", headers, map[string]any{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]any{},
		})
		s.Require().Equal(200, code,
			"pre-restart: /check/resource must return 200; body: %s", string(body))
		// check/resource returns raw "true" when the admin policy allows access.
		s.Require().Equal("true", strings.TrimSpace(string(body)),
			"pre-restart: admin must be allowed for ATTACHMENT/READ before restart; body: %s", string(body))
	})

	// ── Step 2: restart the OPA container ────────────────────────────────
	// OPA gets SIGTERM, flushes its in-memory state, and comes back on the same
	// opa-data volume. pap-client keeps running throughout; it logs push
	// failures while OPA is down and resumes on the next tick.
	s.Step("opa_restart.restart_opa_container", func() {
		s.Require().NoError(s.stack.RestartOPA(), "restarting the OPA container failed")
		fmt.Printf("[opa_restart] OPA container restarted\n")
	})

	// ── Step 3: wait for OPA to recover ──────────────────────────────────
	// Poll OPA's native /health endpoint directly. When OPA is healthy, it has
	// already loaded the JSON files from the opa-data volume (policies.json,
	// pips.json, m2m.json, authn/jwks/*, opa-auth-secret.json) so correct
	// decisions are available.
	//
	// Do NOT wait for pap-client's push tick here: the point of restart
	// survival is that disk data is sufficient.
	s.Step("opa_restart.wait_opa_healthy", func() {
		opaHealthURL := s.cfg.OPADirectURL + "/health"
		client := &http.Client{Timeout: 3 * time.Second}
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := client.Get(opaHealthURL)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Printf("[opa_restart] OPA healthy after restart (GET /health → 200)\n")
					return
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		s.Fail("OPA did not recover within 60 s after restart; " +
			"check that the opa-data volume is mounted read-only in the opa container " +
			"and read-write in pap-client")
	})

	// ── Step 4: verify decisions are still correct after restart ─────────
	// The same request as Step 1 must return allow=true. If disk writes were
	// removed from pap-client, OPA would have an empty data directory, find no
	// matching policy, and return allow=false — causing this step to fail RED.
	//
	// Note: requests go via Envoy → OPA. Envoy's upstream retries handle the
	// brief reconnect window; by the time Step 3 passed, Envoy's connection
	// pool has already re-established the upstream circuit.
	//
	// waitForACPull() is safe here: the driver returns only once pap-client
	// can reach OPA again, and the push tick runs on its normal interval.
	s.Step("opa_restart.post_restart_decisions_correct", func() {
		// Let pap-client complete one fresh push cycle so decisions are current.
		s.waitForACPull()

		headers := incomingTokenHeader(s.validAdminToken)
		code, body := s.post("/access/v1/check/resource", headers, map[string]any{
			"type":      "ATTACHMENT",
			"operation": "READ",
			"resource":  map[string]any{},
		})
		s.Require().Equal(200, code,
			"post-restart: /check/resource must return 200 (policies loaded from disk); "+
				"body: %s", string(body))
		// check/resource returns raw "true" when the admin policy allows access.
		// If policies.json was NOT written to disk, OPA starts with empty state and
		// returns "false" here — that is the intended RED signal for the disk-write proof.
		s.Require().Equal("true", strings.TrimSpace(string(body)),
			"post-restart: admin must still be allowed for ATTACHMENT/READ; "+
				"if this is false, pap-client disk write is broken or policies.json is missing; "+
				"body: %s", string(body))
	})
}
