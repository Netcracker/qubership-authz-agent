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

// token-fetcher is a native Kubernetes sidecar that obtains a Keycloak
// client_credentials token and keeps it refreshed on disk so the backend
// container can use it as a Bearer token for the policy pull loop.
//
// Lifecycle:
//  1. Reads clientId and clientSecret from mounted Secret files.
//  2. POSTs to the configured Keycloak token endpoint.
//  3. Writes the access_token to AUTHZ_PAP_CLIENT_TOKEN_FILE using atomicfile.WriteFile.
//  4. Writes the ready marker file on the first successful fetch; this file is
//     polled by the pod's startupProbe so the pap-client container does not start
//     before the first token is on disk.
//  5. Schedules the next refresh at expires_in - AUTHZ_M2M_RENEW_BEFORE_SECONDS.
//  6. On error: logs a warning, retries with exponential backoff; never exits.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"authz-agent/internal/atomicfile"
)

const (
	defaultClientIDFile     = "/etc/secret/username"
	defaultClientSecretFile = "/etc/secret/password"
	defaultTokenURL         = "http://identity-provider:8080/auth/realms/cloud-common/protocol/openid-connect/token"
	defaultTokenFile        = "/etc/authz/ac-token/token"
	defaultRenewBefore      = 60 * time.Second
	defaultMarkerFile       = "/var/run/authz/token-fetcher-ready"

	maxBackoff     = 5 * time.Minute
	initialBackoff = 2 * time.Second
)

func main() {
	logger := log.New(os.Stdout, "[token-fetcher] ", log.LstdFlags)

	cfg := loadConfig(logger)
	logger.Printf("starting: token_url=%s token_file=%s renew_before=%s",
		cfg.tokenURL, cfg.tokenFile, cfg.renewBefore)

	run(cfg, logger)
}

type config struct {
	clientIDFile     string
	clientSecretFile string
	tokenURL         string
	tokenFile        string
	markerFile       string
	renewBefore      time.Duration
}

func loadConfig(logger *log.Logger) config {
	renewBefore := defaultRenewBefore
	if v := envStr("AUTHZ_M2M_RENEW_BEFORE_SECONDS"); v != "" {
		var secs int
		if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs >= 0 {
			renewBefore = time.Duration(secs) * time.Second
		} else {
			logger.Printf("warn: invalid AUTHZ_M2M_RENEW_BEFORE_SECONDS=%q, using default %s", v, defaultRenewBefore)
		}
	}
	return config{
		clientIDFile:     envStrDefault("AUTHZ_M2M_CLIENT_ID_FILE", defaultClientIDFile),
		clientSecretFile: envStrDefault("AUTHZ_M2M_CLIENT_SECRET_FILE", defaultClientSecretFile),
		tokenURL:         envStrDefault("AUTHZ_M2M_TOKEN_URL", defaultTokenURL),
		tokenFile:        envStrDefault("AUTHZ_PAP_CLIENT_TOKEN_FILE", defaultTokenFile),
		markerFile:       envStrDefault("AUTHZ_M2M_MARKER_FILE", defaultMarkerFile),
		renewBefore:      renewBefore,
	}
}

// run is the main loop: fetch, write, sleep, repeat. Never returns.
func run(cfg config, logger *log.Logger) {
	client := &http.Client{Timeout: 30 * time.Second}
	firstSuccess := false
	backoff := initialBackoff

	for {
		expiresIn, err := fetchAndWrite(cfg, client, logger)
		if err != nil {
			logger.Printf("warn: token fetch failed: %v; retrying in %s", err, backoff)
			time.Sleep(backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Reset backoff on success.
		backoff = initialBackoff

		if !firstSuccess {
			firstSuccess = true
			if err := writeMarker(cfg.markerFile, logger); err != nil {
				logger.Printf("warn: could not write marker file: %v", err)
			}
		}

		sleep := expiresIn - cfg.renewBefore
		if sleep < time.Second {
			sleep = time.Second
		}
		logger.Printf("token refreshed; next refresh in %s", sleep)
		time.Sleep(sleep)
	}
}

// fetchAndWrite obtains a new token and writes it to disk.
// Returns the token lifetime (expires_in) on success.
func fetchAndWrite(cfg config, client *http.Client, logger *log.Logger) (time.Duration, error) {
	clientID, err := readFile(cfg.clientIDFile)
	if err != nil {
		return 0, fmt.Errorf("read clientId from %s: %w", cfg.clientIDFile, err)
	}
	clientSecret, err := readFile(cfg.clientSecretFile)
	if err != nil {
		return 0, fmt.Errorf("read clientSecret from %s: %w", cfg.clientSecretFile, err)
	}

	token, expiresIn, err := fetchToken(client, cfg.tokenURL, clientID, clientSecret)
	if err != nil {
		return 0, fmt.Errorf("fetch token: %w", err)
	}

	if err := atomicfile.WriteFile0600(cfg.tokenFile, []byte(token)); err != nil {
		return 0, fmt.Errorf("write token to %s: %w", cfg.tokenFile, err)
	}
	logger.Printf("token written to %s (expires_in=%s)", cfg.tokenFile, expiresIn)
	return expiresIn, nil
}

// tokenResponse is the relevant subset of the Keycloak token endpoint response.
type tokenResponse struct {
	AccessToken string  `json:"access_token"`
	ExpiresIn   float64 `json:"expires_in"` // seconds; float64 to survive "3600.0"
}

// fetchToken POSTs a client_credentials grant and returns the access token and
// its lifetime.  expires_in from the response is used as the primary source;
// the JWT exp claim is parsed only as a fallback when expires_in is absent.
func fetchToken(client *http.Client, tokenURL, clientID, clientSecret string) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	resp, err := client.PostForm(tokenURL, form)
	if err != nil {
		return "", 0, fmt.Errorf("POST %s: %w", tokenURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("parse token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("empty access_token in response")
	}

	var lifetime time.Duration
	if tr.ExpiresIn > 0 {
		lifetime = time.Duration(tr.ExpiresIn * float64(time.Second))
	} else {
		// Fallback: parse exp from the JWT payload.
		exp, err := jwtExp(tr.AccessToken)
		if err != nil {
			return "", 0, fmt.Errorf("expires_in absent and JWT exp unreadable: %w", err)
		}
		lifetime = time.Until(exp)
		if lifetime < 0 {
			return "", 0, fmt.Errorf("JWT exp is in the past: %v", exp)
		}
	}

	return tr.AccessToken, lifetime, nil
}

// jwtExp decodes the JWT payload (without signature verification — the token
// was just issued by the IdP we trust) and returns the exp claim as a Time.
// Used only when expires_in is absent in the token response.
func jwtExp(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, fmt.Errorf("not a JWT: too few parts")
	}
	payload := parts[1]
	// Base64url padding
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parse JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("exp claim absent or zero")
	}
	return time.Unix(int64(claims.Exp), 0), nil
}

// writeMarker writes the marker file that the startupProbe polls.
func writeMarker(path string, logger *log.Logger) error {
	logger.Printf("writing startup marker: %s", path)
	return atomicfile.WriteFile(path, []byte("ready\n"))
}

func readFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func envStr(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func envStrDefault(key, fallback string) string {
	if v := envStr(key); v != "" {
		return v
	}
	return fallback
}

// min returns the smaller of two durations (stdlib min is Go 1.21+).
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
