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
	"net/http"
	"time"
)

// OPAAuthTransport is an http.RoundTripper that injects an OPA bearer token
// into requests that do not already carry an Authorization header.
//
// Policy-admin uses the same http.Client for both access-control fetches
// (which set their own Authorization: Bearer <ac-token>) and OPA writes
// (which carry no Authorization). The transport adds the OPA token only when
// the caller has not set Authorization, so AC requests pass through unchanged.
//
// Design note: Rego does not support constant-time string comparison, so the
// identity check in system_authz.rego is a plain equality test against
// input.identity (the bare bearer token OPA extracts from the Authorization
// header after stripping the "Bearer " prefix). The OPA auth token is a
// randomly-generated 32-character string (randAlphaNum in the Helm chart),
// which is sufficient for in-cluster write-path protection. Timing attacks on
// this comparison are only feasible from within the cluster, where an attacker
// already has direct network access to OPA's unencrypted port; the token
// therefore functions as an unforgeable secret rather than as a cryptographic
// primitive. See authz-agent-ADR-0077 §Consequences.
type OPAAuthTransport struct {
	// Token is the bearer token to inject; empty disables injection.
	Token string
	// Base is the underlying transport; nil uses http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *OPAAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Token != "" && req.Header.Get("Authorization") == "" {
		req2 := req.Clone(req.Context())
		req2.Header.Set("Authorization", "Bearer "+t.Token)
		req = req2
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// NewOPAClient creates an HTTP client whose transport injects the OPA auth
// token on every request that does not already carry an Authorization header.
// Pass an empty token to get a plain client with the default transport.
func NewOPAClient(token string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &OPAAuthTransport{Token: token},
	}
}
