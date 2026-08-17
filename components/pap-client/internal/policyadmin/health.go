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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// BootstrapProviderResult holds the per-provider outcome from the bootstrap subcommand.
//
// Required is carried here — not just into the published provider map — because
// readiness has to be able to tell "the realm this installation cannot work
// without is missing" from "one of the optional platform realms is absent in
// this namespace" (authz-agent-ADR-0075).
type BootstrapProviderResult struct {
	ID            string `json:"id"`
	Result        string `json:"result"` // "success" | "failure"
	Required      bool   `json:"required,omitempty"`
	FailureReason string `json:"failureReason,omitempty"`
}

// BootstrapStatus is the deterministic artifact written by the bootstrap subcommand.
//
// ConfigError is set when the trusted-providers file itself could not be read
// or parsed. Without it such a run is indistinguishable from "no providers
// configured" — `configuredCount: 0` — and a zero configured count clears every
// threshold, so a Pod whose config was rejected would report Ready and then
// reject every token it is handed. That is the failure this field exists to
// make loud (authz-agent-ADR-0075).
type BootstrapStatus struct {
	Mode            string                    `json:"mode"` // "strict" | "permissive"
	ConfiguredCount int                       `json:"configuredCount"`
	SuccessCount    int                       `json:"successCount"`
	FailureCount    int                       `json:"failureCount"`
	ConfigError     string                    `json:"configError,omitempty"`
	Providers       []BootstrapProviderResult `json:"providers"`
	CompletedAt     string                    `json:"completedAt"`
}

// HealthResponse is the body returned on HTTP 200 (healthy).
//
// PolicyConversion is informational and does not gate readiness: a converter
// that skipped rules is a data problem, and failing the probe would turn it
// into an outage. It is surfaced here so that "Ready but every decision is
// DENY" is visible from outside the log stream.
type HealthResponse struct {
	Status           string           `json:"status"`
	PolicyConversion *ConversionStats `json:"policyConversion,omitempty"`
}

// HealthErrorResponse is the body returned on HTTP 5xx (unhealthy).
type HealthErrorResponse struct {
	Message string              `json:"message"`
	Details *HealthErrorDetails `json:"details,omitempty"`
}

// HealthErrorDetails carries diagnostic context for unhealthy responses.
type HealthErrorDetails struct {
	OPAReady         *bool                   `json:"opaReady,omitempty"`
	ConfigError      string                  `json:"configError,omitempty"`
	Bootstrap        *BootstrapHealthDetails `json:"bootstrap,omitempty"`
	PolicyConversion *ConversionStats        `json:"policyConversion,omitempty"`
}

// BootstrapHealthDetails is a summary of the bootstrap threshold check.
// MissingRequired names the providers marked `required` that did not bootstrap;
// it is what turns "not ready" into an actionable message.
type BootstrapHealthDetails struct {
	Mode            string   `json:"mode"`
	SuccessCount    int      `json:"successCount"`
	RequiredCount   int      `json:"requiredCount"`
	MissingRequired []string `json:"missingRequired,omitempty"`
}

// loadBootstrapStatus reads and parses the status artifact.
// Returns nil when the file is absent or malformed (caller treats this as unhealthy).
func loadBootstrapStatus(path string) (*BootstrapStatus, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap status file not readable: %w", err)
	}
	var status BootstrapStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, fmt.Errorf("bootstrap status file malformed: %w", err)
	}
	if status.Mode != "strict" && status.Mode != "permissive" {
		return nil, fmt.Errorf("bootstrap status has unknown mode: %q", status.Mode)
	}
	if status.CompletedAt == "" {
		return nil, fmt.Errorf("bootstrap status missing completedAt marker")
	}
	return &status, nil
}

// checkOPAReady performs an HTTP GET against opaHealthURL and returns true
// when OPA responds 200.
func checkOPAReady(ctx context.Context, client *http.Client, opaHealthURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opaHealthURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// evaluateHealth applies the mode-aware readiness criteria.
// Returns healthy=true and empty message when all criteria pass.
func evaluateHealth(opaReady bool, status *BootstrapStatus) (healthy bool, message string, details *HealthErrorDetails) {
	if !opaReady {
		return false, "OPA not ready", &HealthErrorDetails{OPAReady: boolPtr(false)}
	}

	if status == nil {
		return false, "bootstrap status unavailable", &HealthErrorDetails{OPAReady: boolPtr(true)}
	}

	// A rejected config reports zero configured providers, and zero clears every
	// count threshold below. Checked first so the Pod stays out of the Service
	// with the parse error in the response body, rather than serving 401s.
	if status.ConfigError != "" {
		return false, "trusted providers configuration is invalid", &HealthErrorDetails{
			OPAReady:    boolPtr(true),
			ConfigError: status.ConfigError,
		}
	}

	// The two thresholds compose. A provider marked `required` must have
	// bootstrapped whatever the mode says, because the generated platform list
	// runs in permissive mode on purpose — three of its four realms are absent
	// in a typical namespace — and permissive alone would let a Pod serve with
	// `cloud-common` missing and only `external` up. An explicit list where
	// every entry is `required: true` is unaffected: both checks then say the
	// same thing.
	var requiredCount int
	if status.Mode == "strict" {
		requiredCount = status.ConfiguredCount
	} else {
		requiredCount = 1
	}

	if missing := missingRequiredProviders(status); len(missing) > 0 {
		return false, "required identity providers did not bootstrap", &HealthErrorDetails{
			OPAReady: boolPtr(true),
			Bootstrap: &BootstrapHealthDetails{
				Mode:            status.Mode,
				SuccessCount:    status.SuccessCount,
				RequiredCount:   requiredCount,
				MissingRequired: missing,
			},
		}
	}

	if status.SuccessCount < requiredCount {
		return false, "bootstrap threshold not met", &HealthErrorDetails{
			OPAReady: boolPtr(true),
			Bootstrap: &BootstrapHealthDetails{
				Mode:          status.Mode,
				SuccessCount:  status.SuccessCount,
				RequiredCount: requiredCount,
			},
		}
	}

	return true, "", nil
}

// missingRequiredProviders lists the providers marked `required` whose
// bootstrap did not succeed, in configuration order. An empty result means
// either that everything required came up or that nothing was marked — in the
// latter case only the mode threshold applies, which is the pre-ADR-0075
// behaviour and what an unmarked legacy config still gets.
func missingRequiredProviders(status *BootstrapStatus) []string {
	var missing []string
	for _, p := range status.Providers {
		if p.Required && p.Result != "success" {
			missing = append(missing, p.ID)
		}
	}
	return missing
}

func boolPtr(v bool) *bool { return &v }

// handleHealth is the GET /health handler registered on the Service mux.
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Message: "method not allowed"})
		return
	}

	// OPA readiness check.
	opaCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	opaReady := checkOPAReady(opaCtx, s.client, s.opaHealthURL)

	// Bootstrap status loading.
	var status *BootstrapStatus
	if s.bootstrapStatusFile != "" {
		var err error
		status, err = loadBootstrapStatus(s.bootstrapStatusFile)
		if err != nil {
			// Distinguish: if OPA is also not ready, prefer the OPA error.
			if opaReady {
				s.logger.Printf("health: bootstrap status error: %v", err)
				writeJSON(w, http.StatusServiceUnavailable, HealthErrorResponse{
					Message: "bootstrap status unavailable",
					Details: &HealthErrorDetails{OPAReady: boolPtr(true)},
				})
				return
			}
		}
	}

	healthy, message, details := evaluateHealth(opaReady, status)

	// Conversion counts are attached to both outcomes; a missing or malformed
	// pull status file simply omits them (the readiness subcommand, not this
	// handler, is what reacts to that).
	conversion := s.loadConversionStats()

	if healthy {
		writeJSON(w, http.StatusOK, HealthResponse{
			Status:           "healthy",
			PolicyConversion: conversion,
		})
		return
	}

	if details == nil {
		details = &HealthErrorDetails{}
	}
	details.PolicyConversion = conversion

	writeJSON(w, http.StatusServiceUnavailable, HealthErrorResponse{
		Message: message,
		Details: details,
	})
}

// loadConversionStats reads the conversion counts from the pull status file.
// Returns nil when the file is absent, unreadable, or was written by a delivery
// mode that does not convert (ConfigMap mount).
func (s *Service) loadConversionStats() *ConversionStats {
	if s.pullStatusFile == "" {
		return nil
	}
	status, err := LoadPullStatus(s.pullStatusFile)
	if err != nil {
		return nil
	}
	return status.Conversion
}
