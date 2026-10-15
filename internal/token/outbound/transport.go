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
}

// NewTransport returns a transport that sends a request through base after
// two additions. It adds each header that opts.Headers returns for the
// request's context and the request does not carry yet. It adds
// Authorization: Bearer with the token of source to a request whose URL
// opts.Authorize accepts and that carries no Authorization of its own;
// while source holds no token, such a request is not sent and fails with
// [ErrNoToken].
//
// The additions go on a copy of the request, so the caller's request, and
// any request an HTTP client derives from it to follow a redirect, never
// holds the token: each redirect is judged by opts.Authorize on its own.
func NewTransport(base http.RoundTripper, source Source, opts TransportOptions) http.RoundTripper {
	return &transport{base: base, source: source, opts: opts}
}

type transport struct {
	base   http.RoundTripper
	source Source
	opts   TransportOptions
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	if t.opts.Headers != nil {
		for name, values := range t.opts.Headers(req.Context()) {
			if out.Header.Get(name) == "" {
				out.Header[http.CanonicalHeaderKey(name)] = slices.Clone(values)
			}
		}
	}
	if t.opts.Authorize != nil && out.Header.Get("Authorization") == "" && t.opts.Authorize(out.URL) {
		token := t.source.Token()
		if token == "" {
			// A RoundTripper closes the request body even when it fails.
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, ErrNoToken
		}
		out.Header.Set("Authorization", "Bearer "+token)
	}
	return t.base.RoundTrip(out)
}

// AllowHosts returns an Authorize function for [TransportOptions] that
// accepts a URL whose host is one of hosts. An entry with a port, such as
// "pip:8080" or "[::1]:8080", accepts that port alone; an entry without one,
// such as "pip", "::1", or "[::1]", accepts every port of that host. Host
// names compare without regard to case.
func AllowHosts(hosts ...string) func(u *url.URL) bool {
	withPort := map[string]bool{}
	anyPort := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(h)
		if _, _, err := net.SplitHostPort(h); err == nil {
			withPort[h] = true
		} else {
			anyPort[strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")] = true
		}
	}
	return func(u *url.URL) bool {
		return withPort[strings.ToLower(u.Host)] || anyPort[strings.ToLower(u.Hostname())]
	}
}
