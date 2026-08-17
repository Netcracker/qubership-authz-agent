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
	"os/exec"
	"strings"
)

// TestReadiness covers readiness-probe behaviour driven by the pull-status latch.
func (s *RuntimeSuite) TestReadiness() {

	// ── Scenario: pap-client healthcheck --readiness exits 0 after pull ──────
	// The setup phase (setup.wait_for_agent) already waited for the PolicyPuller
	// to complete at least one successful pull and write pull-status.json with
	// policiesLoaded=true. Executing the readiness check inside the opa container
	// confirms that the latch was written and the probe command reads it correctly.
	//
	// The command is equivalent to what Kubernetes runs for the readinessProbe:
	//   exec: ["pap-client", "healthcheck", "--readiness"]
	//
	// Note: docker compose exec -T is used to suppress the TTY allocation that
	// would otherwise mangle output in non-interactive CI runs.
	s.Step("readiness.policies_loaded_after_pull", func() {
		project := s.cfg.ComposeProjectName
		cmd := exec.Command(
			"docker", "compose",
			"-p", project,
			"exec", "-T", "pap-client",
			"pap-client", "healthcheck", "--readiness",
		)
		out, err := cmd.CombinedOutput()
		s.Require().NoError(err,
			"pap-client healthcheck --readiness must exit 0 after a successful pull; "+
				"project=%s output: %s", project, strings.TrimSpace(string(out)))
		fmt.Printf("[readiness] healthcheck --readiness passed; output: %s\n", strings.TrimSpace(string(out)))
	})
}
