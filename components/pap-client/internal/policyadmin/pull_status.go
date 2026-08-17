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

package policyadmin

import (
	"encoding/json"
	"os"

	"authz-agent/internal/atomicfile"
)

// PullStatus tracks the fact that the policy pull loop (or MountWatcher) has
// completed at least one successful load of policies into OPA.
//
// Written atomically by PolicyPuller and MountWatcher; read by
// "pap-client healthcheck --readiness" to gate Pod readiness.
//
// PoliciesLoaded is a one-way latch: once set to true it is never reset, even
// when subsequent pulls fail.  This allows the readiness probe to stay green
// when access-control is temporarily unreachable — the policies cached in OPA
// memory are still valid, and removing the Pod from the Service would make
// authorization unavailable rather than better.
//
// When pull is disabled (AUTHZ_PAP_CLIENT_SOURCE_URL empty, interval 0, or ConfigMap
// mount mode), PolicyPuller / MountWatcher writes the status immediately with
// PoliciesLoaded=true and a descriptive Reason so that the readiness probe does
// not block a Pod that was never expected to pull.
type PullStatus struct {
	PoliciesLoaded bool   `json:"policiesLoaded"`
	FirstSuccessAt string `json:"firstSuccessAt,omitempty"`
	LastSuccessAt  string `json:"lastSuccessAt,omitempty"`
	// Reason is populated when the status is written by a "pull disabled"
	// early return rather than an actual successful pull.
	Reason string `json:"reason,omitempty"`
	// Conversion carries the counts from the most recent access-control config
	// conversion. Absent in ConfigMap mount mode, where no conversion runs.
	Conversion *ConversionStats `json:"conversion,omitempty"`
}

// ConversionStats mirrors acconfig.Stats for the status file and the /health
// body. It is declared here rather than reused from acconfig so that reading
// the status file — which "pap-client healthcheck" and the health handler
// both do — does not depend on the converter package.
//
// The counts answer the question a bare policiesLoaded=true cannot: a pull that
// fetched 1294 policy sets and converted none of them is a successful pull by
// every other measure, and it is what an authorization outage looks like from
// the outside.
type ConversionStats struct {
	PolicySets        int `json:"policySets"`
	PolicySetsSkipped int `json:"policySetsSkipped"`
	Rules             int `json:"rules"`
	RulesSkipped      int `json:"rulesSkipped"`
	RulesDenySkipped  int `json:"rulesDenySkipped"`
	Policies          int `json:"policies"`
}

// WritePullStatus atomically writes a PullStatus JSON file to path.
// Silently returns nil for an empty path (feature disabled).
func WritePullStatus(path string, status PullStatus) error {
	if path == "" {
		return nil
	}
	content, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(path, content)
}

// LoadPullStatus reads and parses the pull status file at path.
// Returns a non-nil error (and nil status) when the file is absent or
// malformed; the caller treats the absence as "not loaded yet".
func LoadPullStatus(path string) (*PullStatus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s PullStatus
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
