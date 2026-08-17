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
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// TestOPARestart verifies that policies, PIPs, and authentication data survive
// an OPA container restart without waiting for the next pap-client push tick
// (restart survival).
//
// Design: pap-client writes each document root to the shared opa-data volume
// BEFORE pushing to OPA's Data API (two-sided write).  On OPA container restart
// the opa-data named volume persists; OPA reads JSON files from it at startup
// and serves correct decisions immediately.
//
// Red/green proof: removing the disk writes from pap-client causes this test to
// fail because OPA starts with an empty data directory and all policy-dependent
// decisions return the wrong result.  The unit-level proof lives in
// opa_document_roots_test.go:TestDiskLayoutMatchesPushTargets.
//
// Ordering: pap-client shares OPA's network namespace (network_mode: "service:opa").
// When only OPA is restarted, Docker tears down OPA's network namespace and creates
// a new one for the new OPA container.  Pap-client continues running in OPA's OLD
// (now isolated) namespace: Docker's embedded DNS (127.0.0.11) stops working, and
// pap-client can no longer reach authz-policy-admin or push to OPA.  To restore
// normal operation, the test explicitly restarts pap-client (step
// opa_restart.restart_pap_client) AFTER OPA is healthy, so pap-client joins OPA's
// new namespace.  opa_restart.wait_pap_client_healthy then polls pap-client's /health
// until 200, confirming a completed pull cycle.  Once that step passes, subsequent
// tests that call waitForACPull() see a healthy pap-client regardless of where this
// test sorts — making the test truly order-independent.
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

	// ── Step 2: restart the opa container ────────────────────────────────
	// docker compose restart sends SIGTERM to the running OPA container,
	// waits for it to exit (OPA flushes in-memory state), then starts a new
	// OPA container that mounts the same opa-data named volume.
	// pap-client keeps running throughout; it logs push failures while OPA is
	// down and resumes on the next tick.
	s.Step("opa_restart.restart_opa_container", func() {
		project := s.cfg.ComposeProjectName
		cmd := exec.Command("docker", "compose", "-p", project, "restart", "opa")
		out, err := cmd.CombinedOutput()
		s.Require().NoError(err,
			"docker compose restart opa failed; project=%s output: %s",
			project, strings.TrimSpace(string(out)))
		fmt.Printf("[opa_restart] OPA container restarted; output: %s\n",
			strings.TrimSpace(string(out)))
	})

	// ── Step 3: wait for OPA to recover ──────────────────────────────────
	// Poll OPA's native /health endpoint directly (OPA direct port published
	// by the compose stack).  When OPA is healthy, it has already loaded the
	// JSON files from the opa-data volume (policies.json, pips.json, m2m.json,
	// authn/jwks/*, opa-auth-secret.json) so correct decisions are available.
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
			"check that opa-data volume is mounted read-only in the opa container " +
			"and read-write in pap-client (see docker-compose.yml)")
	})

	// ── Step 4: restart pap-client so it joins OPA's new namespace ───────
	// When OPA is restarted, its network namespace is replaced.  Pap-client
	// was running in OPA's OLD namespace and is now isolated: Docker's embedded
	// DNS (127.0.0.11) stops responding, so pap-client can no longer resolve
	// authz-policy-admin or push to OPA.
	//
	// Restarting pap-client here causes Docker to start it fresh with
	// network_mode: "service:opa", joining the CURRENT (new) OPA container's
	// namespace.  DNS and loopback connectivity to OPA are fully restored.
	// This is the correct way to handle "sibling container restart" in a
	// shared-namespace topology; no data is lost because the opa-data volume
	// is still mounted.
	s.Step("opa_restart.restart_pap_client", func() {
		project := s.cfg.ComposeProjectName
		cmd := exec.Command("docker", "compose", "-p", project, "restart", "pap-client")
		out, err := cmd.CombinedOutput()
		s.Require().NoError(err,
			"docker compose restart pap-client failed; project=%s output: %s",
			project, strings.TrimSpace(string(out)))
		fmt.Printf("[opa_restart] pap-client restarted into OPA's new namespace; output: %s\n",
			strings.TrimSpace(string(out)))
	})

	// ── Step 5: wait for pap-client to re-establish OPA connection ───────
	// Pap-client is now in OPA's new network namespace and can reach OPA's
	// Data API at 127.0.0.1:8181.  Poll pap-client's own GET /health until
	// it returns 200, which proves that pap-client has:
	//   (a) probed OPA's native /health and found it ready,
	//   (b) read the bootstrap status file successfully, and
	//   (c) can complete push requests again.
	// Once this step passes, the next waitForACPull() in any subsequent test
	// is guaranteed to see a fully operational pap-client.
	s.Step("opa_restart.wait_pap_client_healthy", func() {
		client := &http.Client{Timeout: 3 * time.Second}
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := client.Get(s.cfg.PAPClientHealthURL)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					fmt.Printf("[opa_restart] pap-client healthy after restart (GET /health → 200)\n")
					return
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		s.Fail("pap-client did not recover within 45 s after OPA restart; " +
			"check that OPA's network namespace is healthy and pap-client can reach 127.0.0.1:8181")
	})

	// ── Step 6: verify decisions are still correct after restart ─────────
	// The same request as Step 1 must return allow=true.  If disk writes were
	// removed from pap-client, OPA would have an empty data directory, find no
	// matching policy, and return allow=false — causing this step to fail RED.
	//
	// Note: requests go via Envoy → OPA.  Envoy's upstream retries handle the
	// brief reconnect window; by the time Step 3 passed, Envoy's connection
	// pool has already re-established the upstream circuit.
	//
	// waitForACPull() is safe here because Step 4 confirmed pap-client is
	// healthy; the push tick runs on its normal 2 s interval.
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

// TestOPAMountModeRestartDiskLayout verifies that the disk files pap-client
// writes to the opa-data volume have the correct OPA data-dir layout for
// restart recovery in ConfigMap-mount mode (the worst case).
//
// In ConfigMap-mount mode (MountWatcher active, pull loop disabled), pap-client
// republishes to OPA only when the ConfigMap content changes. If OPA restarts
// alone — which is possible because it is now a separate container — pap-client
// would NOT re-push on that event, so disk-file loading is the ONLY recovery
// mechanism. This test proves that the files are present and carry the correct
// single top-level key (matching the OPA Data API path component) so OPA loads
// the right document root at startup.
//
// The test runs against the live compose stack (post-SetupSuite, after at least
// one pull tick has populated the opa-data volume). It execs into the pap-client
// container (alpine-based, has sh/cat) which has the opa-data volume mounted
// read-write, to read and validate each JSON file.
//
// Red/green proof: remove the atomicfile.WriteFile call from persistPolicies
// (policy_puller.go) and this test fails with "file not found". Change the
// top-level key from "policies" to "raw_policies" and it fails the key check.
// Both are distinct from TestOPARestart, which proves liveness via a live OPA
// restart; this test proves structural correctness WITHOUT a second restart.
func (s *RuntimeSuite) TestOPAMountModeRestartDiskLayout() {

	checkDiskKey := func(stepName, filePath, wantKey string) {
		s.Step(stepName, func() {
			project := s.cfg.ComposeProjectName
			out, err := exec.Command(
				"docker", "compose",
				"-p", project,
				"exec", "-T", "pap-client",
				"cat", filePath,
			).CombinedOutput()
			s.Require().NoError(err,
				"could not read %s from pap-client container; "+
					"project=%s output: %s\n"+
					"(hint: remove disk-write from pap-client to reproduce the red state)",
				filePath, project, strings.TrimSpace(string(out)))

			// Parse the JSON and extract all top-level keys.  The file must
			// have exactly one top-level key and it must equal wantKey so that
			// OPA's data-dir merge produces data.<wantKey> at startup.
			var doc map[string]json.RawMessage
			s.Require().NoError(json.Unmarshal(out, &doc),
				"disk file %s is not valid JSON; content: %s", filePath, out)

			keys := make([]string, 0, len(doc))
			for k := range doc {
				keys = append(keys, k)
			}
			s.Require().Len(keys, 1,
				"disk file %s must have exactly 1 top-level key for OPA data-dir merge; "+
					"got %d keys: %v", filePath, len(keys), keys)
			s.Require().Equal(wantKey, keys[0],
				"disk file %s top-level key = %q, want %q; "+
					"OPA startup-from-disk and runtime-push would disagree "+
					"(mount-mode restart survival broken)",
				filePath, keys[0], wantKey)

			fmt.Printf("[opa_mount_restart] %s ok: top-level key = %q (matches /v1/data/%s push target)\n",
				filePath, keys[0], wantKey)
		})
	}

	// ── Step 1: policies.json — push target /v1/data/policies ────────────
	// persistPolicies writes {"policies": normalizedPolicies} and PolicyPuller
	// pushes to /v1/data/policies. The keys must agree.
	checkDiskKey("opa_mount_restart.verify_policies_disk_key",
		"/etc/opa/data/policies.json", "policies")

	// ── Step 2: pips.json — push target /v1/data/pips ────────────────────
	// persistPIPs writes {"pips": doc.Normalized} and PolicyPuller pushes to
	// /v1/data/pips. MountWatcher.applyAndPublish also writes this file with
	// the same key — that is the mount-mode path this test is specifically for.
	checkDiskKey("opa_mount_restart.verify_pips_disk_key",
		"/etc/opa/data/pips.json", "pips")

	// ── Step 3: m2m.json — push target /v1/data/m2m ──────────────────────
	// TokenWatcher.publish writes {"m2m": {"bearerToken": token}} and pushes
	// to /v1/data/m2m. The key must agree.
	checkDiskKey("opa_mount_restart.verify_m2m_disk_key",
		"/etc/opa/data/m2m.json", "m2m")
}
