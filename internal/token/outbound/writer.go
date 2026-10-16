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

package outbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultHTTPTimeout is the timeout of the client a [Writer] sends its
// requests with when [WriterConfig.Client] is nil.
const DefaultHTTPTimeout = 10 * time.Second

// The pauses between two failed attempts of [Writer.Run] start at
// defaultFirstBackoff and double after every failure, up to maxBackoff.
const (
	defaultFirstBackoff = 2 * time.Second
	maxBackoff          = 5 * time.Minute
)

// maxTokenResponseBytes bounds the body of a token response, 1 MiB
// (1048576 bytes).
const maxTokenResponseBytes = 1 << 20

// WriterConfig names the token endpoint, the client credentials, and the
// file a [Writer] keeps the token in.
type WriterConfig struct {
	// TokenURL is the token endpoint of the identity provider, an absolute
	// http or https URL.
	TokenURL string
	// ClientIDFile and ClientSecretFile hold the client credentials. Both
	// are read on every request, so rotated credentials take effect without
	// a restart.
	ClientIDFile     string
	ClientSecretFile string
	// Path is the file the token is written to. Its directory has to exist;
	// the file is replaced whole, so a reader never sees half a token.
	Path string
	// Client sends the token requests. Nil means a client with the proxy
	// settings of the environment and DefaultHTTPTimeout that follows no
	// redirect, so the client secret goes to TokenURL alone and a redirect
	// fails the request.
	Client *http.Client
}

// Writer obtains a token from an identity provider with the client
// credentials grant and keeps it in a file for a [FileSource] to read.
type Writer struct {
	cfg WriterConfig
	log Logger
	// firstBackoff is the pause after the first failed attempt in Run.
	firstBackoff time.Duration
	// wait pauses Run for d between two attempts, and reports false when
	// ctx ends first.
	wait func(ctx context.Context, d time.Duration) bool
}

// NewWriter returns a writer for cfg, or an error when cfg names no token
// file, no credential file, or a TokenURL that is not an absolute http or
// https URL. A nil log discards the diagnostics.
func NewWriter(cfg WriterConfig, log Logger) (*Writer, error) {
	u, err := url.Parse(cfg.TokenURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("token URL %q is not an absolute http or https URL", cfg.TokenURL)
	}
	switch {
	case cfg.ClientIDFile == "":
		return nil, errors.New("no client id file")
	case cfg.ClientSecretFile == "":
		return nil, errors.New("no client secret file")
	case cfg.Path == "":
		return nil, errors.New("no token file")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: DefaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if log == nil {
		log = discard{}
	}
	return &Writer{cfg: cfg, log: log, firstBackoff: defaultFirstBackoff, wait: sleep}, nil
}

// Run keeps a valid token in the file until ctx ends. It requests a token at
// once, and the next one when 70% of the current token's lifetime has passed,
// but no sooner than a second later. A failed attempt leaves the previous
// token in the file and is retried with pauses that double from two seconds
// up to five minutes.
func (w *Writer) Run(ctx context.Context) {
	backoff := w.firstBackoff
	for {
		var pause time.Duration
		lifetime, err := w.Refresh(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			w.log.Warnf("outbound token: %v; retrying in %s", err, backoff)
			pause, backoff = backoff, nextBackoff(backoff)
		} else {
			pause = renewal(lifetime)
			backoff = w.firstBackoff
		}
		if !w.wait(ctx, pause) {
			return
		}
	}
}

// sleep waits for d and reports true, or reports false as soon as ctx ends.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// nextBackoff is the pause after the failure that follows one paused for
// backoff: twice as long, up to maxBackoff.
func nextBackoff(backoff time.Duration) time.Duration {
	return min(backoff*2, maxBackoff)
}

// renewal is the wait before the next request for a token that lives
// lifetime: 70% of the lifetime, and at least a second.
func renewal(lifetime time.Duration) time.Duration {
	return max(lifetime/10*7, time.Second)
}

// Refresh requests one token and writes it to the file, and returns how long
// the token lives. The lifetime is the response's expires_in, or the time
// left until the token's exp claim when the response has none. A lifetime
// longer than a Duration can hold, about 292 years, is returned as the
// longest Duration. On an error the file keeps its previous content.
func (w *Writer) Refresh(ctx context.Context) (time.Duration, error) {
	clientID, err := readSecret(w.cfg.ClientIDFile)
	if err != nil {
		return 0, fmt.Errorf("client id: %w", err)
	}
	clientSecret, err := readSecret(w.cfg.ClientSecretFile)
	if err != nil {
		return 0, fmt.Errorf("client secret: %w", err)
	}
	token, lifetime, err := w.request(ctx, clientID, clientSecret)
	if err != nil {
		return 0, err
	}
	if err := writeAtomically(w.cfg.Path, token); err != nil {
		return 0, err
	}
	w.log.Infof("outbound token: wrote a token that lives %s to %s", lifetime.Round(time.Second), w.cfg.Path)
	return lifetime, nil
}

func (w *Writer) request(ctx context.Context, clientID, clientSecret string) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := w.cfg.Client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", 0, fmt.Errorf("POST %s: read body: %w", w.cfg.TokenURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", 0, fmt.Errorf("POST %s: HTTP %d", w.cfg.TokenURL, resp.StatusCode)
	}
	var tr struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("POST %s: token response: %w", w.cfg.TokenURL, err)
	}
	if tr.AccessToken == "" {
		return "", 0, fmt.Errorf("POST %s: token response has no access_token", w.cfg.TokenURL)
	}
	if tr.ExpiresIn > 0 {
		return tr.AccessToken, fromSeconds(tr.ExpiresIn), nil
	}
	exp, err := expiry(tr.AccessToken)
	if err != nil {
		return "", 0, fmt.Errorf("POST %s: token response has no expires_in, and %w", w.cfg.TokenURL, err)
	}
	lifetime := fromSeconds(exp - float64(time.Now().UnixNano())/float64(time.Second))
	if lifetime <= 0 {
		expired := time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
		return "", 0, fmt.Errorf("POST %s: the token expired at %s", w.cfg.TokenURL, expired)
	}
	return tr.AccessToken, lifetime, nil
}

// fromSeconds converts a count of seconds to a Duration. A count of more
// seconds than a Duration can hold, about 292 years, gives the longest
// Duration; s must not be below the range of a Duration.
func fromSeconds(s float64) time.Duration {
	ns := s * float64(time.Second)
	if ns >= math.MaxInt64 {
		return math.MaxInt64
	}
	return time.Duration(ns)
}

// expiry reads the exp claim of a JWT without verifying it and returns it in
// seconds since the Unix epoch. The token comes straight from the provider,
// and the time only decides when to ask for the next one.
func expiry(token string) (float64, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, errors.New("the token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, errors.New("the token payload is not base64url")
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp <= 0 {
		return 0, errors.New("the token has no exp claim")
	}
	return claims.Exp, nil
}

func readSecret(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return value, nil
}

// writeAtomically replaces the file at path with token: it writes a
// temporary file, readable by its owner alone, in the same directory and
// renames it over path.
func writeAtomically(path, token string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	_, writeErr := tmp.WriteString(token)
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write token: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write token: %w", err)
	}
	return nil
}
