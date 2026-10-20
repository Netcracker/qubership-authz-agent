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
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// TransportOptions decides which requests a transport from [NewTransport]
// changes and how.
type TransportOptions struct {
	// Authorize reports whether a request to u carries the token; nil sends
	// the token nowhere.
	Authorize func(u *url.URL) bool
	// Headers returns the headers to add from the request's context, such
	// as the request ID and the tracing headers of the request being
	// decided; nil adds none.
	Headers func(ctx context.Context) http.Header
	// Unauthorized runs when a request that carried the token gets a 401
	// response; nil does nothing. The usual choice is [Writer.Renew], which
	// replaces a token the service no longer accepts. It runs on the
	// request's goroutine before the response is returned, and the request
	// is not sent again.
	Unauthorized func()
}

// NewTransport returns a transport that sends a request through base after
// two additions. It adds each header that opts.Headers returns for the
// request's context and the request does not carry yet. It adds
// Authorization: Bearer with the result of token to a request whose URL
// opts.Authorize accepts and that carries no Authorization of its own;
// while token returns "", such a request is not sent and fails with
// [ErrNoToken]. token is called for every such request, possibly from
// several goroutines at once; [FileSource.Token] is such a function.
//
// The additions go on a copy of the request, so the caller's request, and
// any request an HTTP client derives from it to follow a redirect, never
// holds the token: each redirect is judged by opts.Authorize on its own.
func NewTransport(base http.RoundTripper, token func() string, opts TransportOptions) http.RoundTripper {
	return &transport{base: base, token: token, opts: opts}
}

type transport struct {
	base  http.RoundTripper
	token func() string
	opts  TransportOptions
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	t.addHeaders(out)
	if t.opts.Authorize != nil && out.Header.Get("Authorization") == "" && t.opts.Authorize(out.URL) {
		token := t.token()
		if token == "" {
			// A RoundTripper closes the request body even when it fails.
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, ErrNoToken
		}
		out.Header.Set("Authorization", "Bearer "+token)
		resp, err := t.base.RoundTrip(out)
		if err == nil && resp.StatusCode == http.StatusUnauthorized && t.opts.Unauthorized != nil {
			t.opts.Unauthorized()
		}
		return resp, err
	}
	return t.base.RoundTrip(out)
}

// addHeaders adds to out each header that opts.Headers returns for the
// context of out and that out does not carry yet.
func (t *transport) addHeaders(out *http.Request) {
	if t.opts.Headers == nil {
		return
	}
	for name, values := range t.opts.Headers(out.Context()) {
		if out.Header.Get(name) == "" {
			out.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
		}
	}
}

// AllowHosts returns an Authorize function for [TransportOptions] that
// accepts a URL whose scheme and host match an entry of hosts. An entry is
// a host with an optional port, such as "pip", "pip:8443", "::1", or
// "[::1]:8443", and accepts https URLs. Prefixed with "http://", it accepts
// http URLs instead, so the token travels in clear text only to a host
// named for it; an "https://" prefix changes nothing. An entry with a port
// accepts that port alone, and a URL without a port has the default port of
// its scheme, 443 for https and 80 for http. An entry without a port
// accepts every port of that host. Host names compare without regard to
// case.
func AllowHosts(hosts ...string) func(u *url.URL) bool {
	type entry struct{ scheme, host, port string }
	allowed := map[entry]bool{}
	for _, h := range hosts {
		h = strings.ToLower(h)
		scheme := "https"
		if rest, ok := strings.CutPrefix(h, "http://"); ok {
			scheme, h = "http", rest
		} else {
			h = strings.TrimPrefix(h, "https://")
		}
		host, port, err := net.SplitHostPort(h)
		if err != nil {
			host, port = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"), ""
		}
		allowed[entry{scheme, host, port}] = true
	}
	defaultPort := map[string]string{"https": "443", "http": "80"}
	return func(u *url.URL) bool {
		scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
		port := u.Port()
		if port == "" {
			port = defaultPort[scheme]
		}
		return allowed[entry{scheme, host, ""}] || allowed[entry{scheme, host, port}]
	}
}
