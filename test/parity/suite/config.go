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

package paritysuite

import (
	"os"
	"strings"
)

// Config holds every PARITY_* env-var the suite consumes. Defaults align with
// the Step 2 port block (PARITY_AC_PORT=28090, PARITY_PIP_PORT=28091,
// PARITY_IDP_PORT=25557) so a developer running the suite on a freshly
// bootstrapped Step 2 stack does not need to export anything.
type Config struct {
	// ACBaseURL is the public API base URL of the active parity target, e.g.
	// http://localhost:28090 (legacy) or http://localhost:28100 (authz-agent).
	ACBaseURL string

	// IDPBaseURL is the active stack's parity-realm base URL, e.g.
	// http://localhost:25557/auth/realms/parity or
	// http://localhost:25558/auth/realms/parity.
	IDPBaseURL string

	// AuthzAdminBaseURL is the authz-agent pap-client base URL. The legacy
	// profile ignores it; kept for backward compatibility.
	AuthzAdminBaseURL string

	// ACStubBaseURL is the base URL of the authz-policy-admin that serves the access-control
	// v3 config API to the PolicyPuller.  The authz-agent seeder uploads simplified
	// policies here so the puller can fetch them.  Default http://localhost:28093.
	ACStubBaseURL string

	// M2MClientID / M2MClientSecret are the client credentials the suite
	// uses for Authorization: Bearer <M2M>. Default to the parity-m2m
	// client Step 2 seeds into the parity realm.
	M2MClientID     string
	M2MClientSecret string

	// EndUserClientID / EndUserClientSecret are the
	// password-grant-capable client credentials the suite uses to obtain
	// end-user tokens for Incoming-Token: Bearer <end-user>. The realm
	// seed provides this client per D-N; the defaults are placeholders.
	EndUserClientID     string
	EndUserClientSecret string

	// EndUserPassword is the password applied to every parity-* test user
	// from the static realm seed per D-N. Every test user shares the same password
	// because the realm seed is static and the password policy is uniform.
	EndUserPassword string

	// PipMockControlURL is the base URL of the pip-mock service on the
	// host-published port — used for POST /pip-stub/configure and
	// GET /pip-stub/reset. Default http://localhost:28091.
	PipMockControlURL string

	// EAMockControlURL is the base URL of the entitlements-mock service
	// (part of the parity compose stack per D-U). Default http://localhost:28092.
	EAMockControlURL string

	// TenantID is the value the suite sends in the tenant_id query param
	// (D-V item 6). Defaults to "default" — the tenant the Step 2 smoke
	// fixtures use.
	TenantID string

	// DomainName is the simplified-policy domain the suite seeds into per
	// D-L (always "PARITY" in Step 3).
	DomainName string

	// Profile is the active PARITY_PROFILE. The only supported value is
	// "authz-agent" (golden collection cannot run from this repository).
	Profile string
}

// LoadConfig builds a Config from the PARITY_* environment variables. Missing
// values fall back to the authz-agent port-block defaults so a freshly
// brought-up parity stack needs no extra shell plumbing.
func LoadConfig() Config {
	profile := normalizeProfile(envOr("PARITY_PROFILE", "authz-agent"))

	return Config{
		ACBaseURL:           envOr("PARITY_AC_BASE_URL", defaultACBaseURL(profile)),
		IDPBaseURL:          envOr("PARITY_IDP_BASE_URL", defaultIDPBaseURL(profile)),
		AuthzAdminBaseURL:   envOr("PARITY_AUTHZ_ADMIN_BASE_URL", "http://localhost:"+envOr("PARITY_AUTHZ_ADMIN_PORT", "28182")),
		ACStubBaseURL:       envOr("PARITY_AUTHZ_POLICY_ADMIN_BASE_URL", "http://localhost:"+envOr("PARITY_AUTHZ_POLICY_ADMIN_PORT", "28093")),
		M2MClientID:         envOr("PARITY_M2M_CLIENT_ID", "parity-m2m"),
		M2MClientSecret:     envOr("PARITY_M2M_CLIENT_SECRET", "ParityM2MSecret1!@#"),
		EndUserClientID:     envOr("PARITY_END_USER_CLIENT_ID", "parity-end-user"),
		EndUserClientSecret: envOr("PARITY_END_USER_CLIENT_SECRET", "ParityEndUserSecret1!@#"),
		EndUserPassword:     envOr("PARITY_END_USER_PASSWORD", "ParityPass1!@#"),
		PipMockControlURL:   envOr("PARITY_PIP_MOCK_CONTROL_URL", "http://localhost:"+envOr("PARITY_PIP_PORT", "28191")),
		EAMockControlURL:    envOr("PARITY_EA_MOCK_CONTROL_URL", "http://localhost:"+envOr("PARITY_EA_PORT", "28192")),
		TenantID:            envOr("PARITY_TENANT_ID", "default"),
		DomainName:          envOr("PARITY_DOMAIN_NAME", "PARITY"),
		Profile:             profile,
	}
}

func normalizeProfile(profile string) string {
	trimmed := strings.TrimSpace(strings.ToLower(profile))
	if trimmed == "" {
		return "authz-agent"
	}
	return trimmed
}

func isAuthzAgentProfile(profile string) bool {
	return normalizeProfile(profile) == "authz-agent"
}

func defaultACBaseURL(profile string) string {
	portKey, fallback := "PARITY_AC_PORT", "28090"
	if isAuthzAgentProfile(profile) {
		portKey, fallback = "PARITY_AUTHZ_PORT", "28100"
	}
	return "http://localhost:" + envOr(portKey, fallback)
}

func defaultIDPBaseURL(profile string) string {
	portKey, fallback := "PARITY_IDP_PORT", "25557"
	if isAuthzAgentProfile(profile) {
		portKey, fallback = "PARITY_AUTHZ_IDP_PORT", "25558"
	}
	return "http://localhost:" + envOr(portKey, fallback) + "/auth/realms/parity"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
