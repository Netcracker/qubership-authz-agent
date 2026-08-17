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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// UserProfile selects which seeded parity test user to acquire an end-user
// token for. Values map to the users D-N locks into parity-realm.json.
type UserProfile int

const (
	// UserProfileReader is parity-reader (realm role ROLE_PARITY_READER,
	// department=finance, tier=gold). Drives single-role allow paths.
	UserProfileReader UserProfile = iota
	// UserProfileReviewer is parity-reviewer (realm role ROLE_PARITY_REVIEWER,
	// department=compliance, tier=silver). Drives AGG rows 61/62 and row 47's
	// distinct-subject variant.
	UserProfileReviewer
	// UserProfileMultiRole is parity-multi-role (both
	// ROLE_PARITY_READER and ROLE_PARITY_REVIEWER, department=engineering,
	// tier=platinum). Drives AGG rows 66/67.
	UserProfileMultiRole
	// UserProfileOther is parity-other (realm role ROLE_PARITY_OTHER).
	// Matches no seeded policy; used to prove deny paths. Claims:
	// department=sales, tier=bronze.
	UserProfileOther
	// UserProfileAnonBaseline is parity-anon-baseline — seeded but not
	// consumed by any Step-3 test. Exists so future work can reach for a
	// second unrelated end user without editing the realm.
	UserProfileAnonBaseline
)

// Username returns the Keycloak username for the profile. The realm seed
// creates each of these users with the password in Config.EndUserPassword.
func (p UserProfile) Username() string {
	switch p {
	case UserProfileReader:
		return "parity-reader"
	case UserProfileReviewer:
		return "parity-reviewer"
	case UserProfileMultiRole:
		return "parity-multi-role"
	case UserProfileOther:
		return "parity-other"
	case UserProfileAnonBaseline:
		return "parity-anon-baseline"
	}
	return ""
}

// TokenBundle is the per-request set of tokens the Go helper layer plants
// into Authorization / Incoming-Token / Authorization-Type headers per D-V
// items 2/3/4. Non-anonymous flows fill M2M + EndUser; anonymous flows fill
// M2M only and set Anonymous=true.
type TokenBundle struct {
	M2M       string
	EndUser   string
	Anonymous bool
}

// TokenFactory minted tokens from the parity Keycloak realm. Tokens are
// cached per (grant, key) tuple until expiry; the cache is a simple in-memory
// map guarded by a mutex.
type TokenFactory struct {
	cfg    Config
	client *http.Client

	mu    sync.Mutex
	cache map[string]tokenEntry
}

type tokenEntry struct {
	accessToken string
	expiresAt   time.Time
}

// NewTokenFactory builds a TokenFactory bound to the given config. The
// underlying HTTP client has a 10s timeout, matching the tests/integration/testify
// helpers.go convention per D-I.
func NewTokenFactory(cfg Config) *TokenFactory {
	return &TokenFactory{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		cache:  make(map[string]tokenEntry),
	}
}

// M2MToken returns the cached parity-m2m client_credentials access token,
// minting a fresh one if the cache entry is missing or close to expiry.
func (tf *TokenFactory) M2MToken() (string, error) {
	return tf.cachedToken("m2m", func() (tokenEntry, error) {
		return tf.clientCredentialsGrant(tf.cfg.M2MClientID, tf.cfg.M2MClientSecret)
	})
}

// EndUserToken returns a cached access token for the given UserProfile,
// minting a fresh one via password grant against parity-end-user if the
// cache entry is missing or close to expiry.
func (tf *TokenFactory) EndUserToken(profile UserProfile) (string, error) {
	key := "enduser:" + profile.Username()
	return tf.cachedToken(key, func() (tokenEntry, error) {
		return tf.passwordGrant(profile.Username())
	})
}

func (tf *TokenFactory) cachedToken(key string, minter func() (tokenEntry, error)) (string, error) {
	tf.mu.Lock()
	entry, ok := tf.cache[key]
	tf.mu.Unlock()
	if ok && time.Until(entry.expiresAt) > 30*time.Second {
		return entry.accessToken, nil
	}

	fresh, err := minter()
	if err != nil {
		return "", err
	}

	tf.mu.Lock()
	tf.cache[key] = fresh
	tf.mu.Unlock()
	return fresh.accessToken, nil
}

func (tf *TokenFactory) clientCredentialsGrant(clientID, clientSecret string) (tokenEntry, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	return tf.tokenRequest(form)
}

func (tf *TokenFactory) passwordGrant(username string) (tokenEntry, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", tf.cfg.EndUserClientID)
	form.Set("client_secret", tf.cfg.EndUserClientSecret)
	form.Set("username", username)
	form.Set("password", tf.cfg.EndUserPassword)
	form.Set("scope", "openid")
	return tf.tokenRequest(form)
}

func (tf *TokenFactory) tokenRequest(form url.Values) (tokenEntry, error) {
	endpoint := strings.TrimRight(tf.cfg.IDPBaseURL, "/") + "/protocol/openid-connect/token"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenEntry{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tf.client.Do(req)
	if err != nil {
		return tokenEntry{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return tokenEntry{}, fmt.Errorf("token request failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return tokenEntry{}, fmt.Errorf("decode token response: %w", err)
	}
	if payload.AccessToken == "" {
		return tokenEntry{}, fmt.Errorf("empty access_token in response: %s", string(body))
	}
	lifetime := time.Duration(payload.ExpiresIn) * time.Second
	if lifetime == 0 {
		lifetime = 5 * time.Minute
	}
	return tokenEntry{accessToken: payload.AccessToken, expiresAt: time.Now().Add(lifetime)}, nil
}
