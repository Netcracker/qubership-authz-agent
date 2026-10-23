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
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
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

// minRenewInterval is the shortest time between two token requests that
// [Writer.Renew] starts, so a service that refuses every token costs at
// most one token request per 30 seconds.
const minRenewInterval = 30 * time.Second

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
	// BasicAuth sends the client id and secret in an HTTP Basic
	// Authorization header, each form-encoded first, as RFC 6749, section
	// 2.3.1, requires. Without it they go in the form body.
	BasicAuth bool
	// Written runs after each token is written to Path; nil does nothing.
	// The usual choice is [FileSource.Reload] of the source that reads
	// Path, so the new token is used at once.
	Written func()
}

// Writer obtains a token from an identity provider with the client
// credentials grant and keeps it in a file for a [FileSource] to read.
type Writer struct {
	cfg WriterConfig
	log Logger
	// firstBackoff is the pause after the first failed attempt in Run.
	firstBackoff time.Duration
	// wait pauses Run for d between two attempts, or until Renew asks for a
	// token, and reports false when ctx ends first.
	wait func(ctx context.Context, d time.Duration) bool
	// renew holds a pending request from Renew.
	renew chan struct{}
	// requested is when the last token request started, whatever its
	// outcome, in Unix nanoseconds; zero before the first one.
	requested atomic.Int64
	// now is the clock requested and Renew read.
	now func() time.Time
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
	w := &Writer{cfg: cfg, log: log, firstBackoff: defaultFirstBackoff, renew: make(chan struct{}, 1), now: time.Now}
	w.wait = w.sleep
	return w, nil
}

// Run keeps a valid token in the file until ctx ends. It requests a token at
// once, and the next one when 70% of the current token's lifetime has passed,
// but no sooner than a second later, or as soon as [Writer.Renew] asks. A
// failed attempt leaves the previous token in the file and is retried with
// pauses that double from two seconds up to five minutes; Renew can start
// an attempt sooner.
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
		// The request that just ended answers a Renew that came during it.
		select {
		case <-w.renew:
		default:
		}
		if !w.wait(ctx, pause) {
			return
		}
	}
}

// Renew asks Run to request a new token at once, as when a service has
// refused the current one with 401. It does nothing within 30 seconds after
// the start of the previous token request, whether that request succeeded
// or failed, and it does not wait for the new token.
func (w *Writer) Renew() {
	if w.now().Sub(time.Unix(0, w.requested.Load())) < minRenewInterval {
		return
	}
	select {
	case w.renew <- struct{}{}:
	default:
	}
}

// sleep waits for d or for a request from Renew and reports true, or
// reports false as soon as ctx ends.
func (w *Writer) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	case <-w.renew:
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
// the token lives. The lifetime is the response's expires_in, at most
// 2147483647 seconds (about 68 years), or the time left until the token's
// exp claim when the response has none. An exp further ahead than a
// Duration can hold, about 292 years, gives the longest Duration. On an
// error the file keeps its previous content.
func (w *Writer) Refresh(ctx context.Context) (time.Duration, error) {
	w.requested.Store(w.now().UnixNano())
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
	if w.cfg.Written != nil {
		w.cfg.Written()
	}
	w.log.Infof("outbound token: wrote a token that lives %s to %s", lifetime.Round(time.Second), w.cfg.Path)
	return lifetime, nil
}

func (w *Writer) request(ctx context.Context, clientID, clientSecret string) (string, time.Duration, error) {
	style := oauth2.AuthStyleInParams
	if w.cfg.BasicAuth {
		style = oauth2.AuthStyleInHeader
	}
	grant := clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecret, TokenURL: w.cfg.TokenURL, AuthStyle: style}
	token, err := grant.Token(context.WithValue(ctx, oauth2.HTTPClient, w.cfg.Client))
	var refused *oauth2.RetrieveError
	var unsent *url.Error
	switch {
	case errors.As(err, &refused):
		// The message is built from the fields: RetrieveError.Error holds the
		// whole response body, up to 1 MiB, when the response names no error.
		return "", 0, fmt.Errorf("POST %s: HTTP %d%s", w.cfg.TokenURL, refused.Response.StatusCode, oauthError(refused))
	case errors.As(err, &unsent):
		// The error of http.Client.Do names the method and the URL already.
		return "", 0, err
	case err != nil:
		return "", 0, fmt.Errorf("POST %s: %w", w.cfg.TokenURL, err)
	}
	// Token sets Expiry from expires_in, a count of whole seconds, as the
	// response arrives, and leaves it zero when the response has none;
	// rounding gives the count back.
	if lifetime := time.Until(token.Expiry).Round(time.Second); lifetime > 0 {
		return token.AccessToken, lifetime, nil
	}
	exp, err := expiry(token.AccessToken)
	if err != nil {
		return "", 0, fmt.Errorf("POST %s: token response has no expires_in, and %w", w.cfg.TokenURL, err)
	}
	left := exp - float64(time.Now().UnixNano())/float64(time.Second)
	if left <= 0 {
		expired := expiresAt(token.AccessToken).UTC().Format(time.RFC3339)
		return "", 0, fmt.Errorf("POST %s: the token expired at %s", w.cfg.TokenURL, expired)
	}
	return token.AccessToken, fromSeconds(left), nil
}

// oauthError returns the error member of an OAuth error response (RFC 6749,
// section 5.2) and its error_description, as text to append to an error
// message, or "" when the response names no error. The provider wrote both
// values and the message goes into a log line, so each is quoted and cut:
// the error to 64 runes, the description to 200.
func oauthError(e *oauth2.RetrieveError) string {
	if e.ErrorCode == "" {
		return ""
	}
	text := ", error " + quoted(e.ErrorCode, 64)
	if e.ErrorDescription != "" {
		text += ": " + quoted(e.ErrorDescription, 200)
	}
	return text
}

// quoted quotes s, cut to its first limit runes with "..." after the cut.
func quoted(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return strconv.Quote(s)
	}
	return strconv.Quote(string(runes[:limit])) + "..."
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
// seconds since the Unix epoch. The token is the service's own, from the
// provider's token response or from the file a [FileSource] reads, and its
// exp decides when the Writer asks for the next token and until when
// [FileSource.Token] returns it.
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
		Exp *float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return 0, errors.New("the token has no exp claim")
	}
	return *claims.Exp, nil
}

// maxExp is the latest exp that expiresAt takes as a time, 2^53 - 1
// (9007199254740991) seconds after the epoch, the largest integer I-JSON
// (RFC 7493) allows.
const maxExp = 1<<53 - 1

// expiresAt returns the time the exp claim of token names, without
// verifying the token. An exp of zero or below gives the Unix epoch, a time
// long past. A token that is not a JWT with an exp claim, or whose exp is
// later than maxExp, gives the zero time, which stands for no expiry.
func expiresAt(token string) time.Time {
	exp, err := expiry(token)
	switch {
	case err != nil || exp > maxExp:
		return time.Time{}
	case exp <= 0:
		return time.Unix(0, 0)
	}
	return time.Unix(int64(exp), 0)
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
