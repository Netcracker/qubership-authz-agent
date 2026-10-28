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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// recorder is a server that records the headers of every request it gets.
type recorder struct {
	srv *httptest.Server

	mu      sync.Mutex
	headers []http.Header
}

func newRecorder(t *testing.T, handler http.HandlerFunc) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		if handler != nil {
			handler(w, req)
		}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) requests() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headers
}

// send sends one GET to target through rt and returns the headers the
// server received.
func send(t *testing.T, rt http.RoundTripper, target *recorder, header http.Header) http.Header {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target.srv.URL+"/pip", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_ = resp.Body.Close()
	got := target.requests()
	return got[len(got)-1]
}

func hostOf(t *testing.T, r *recorder) string {
	t.Helper()
	u, err := url.Parse(r.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

// Both servers listen on 127.0.0.1, so the port alone tells them apart.
func TestTransport_AddsTheTokenForAnAuthorizedHostOnly(t *testing.T) {
	pip := newRecorder(t, nil)
	other := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})
	tests := []struct {
		name   string
		target *recorder
		want   string
	}{
		{"authorized host", pip, "Bearer tok-1"},
		{"other host", other, ""},
	}
	for _, tt := range tests {
		if got := send(t, rt, tt.target, nil).Get("Authorization"); got != tt.want {
			t.Errorf("%s: Authorization = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestTransport_KeepsAnAuthorizationTheRequestCarries(t *testing.T) {
	pip := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})
	got := send(t, rt, pip, http.Header{"Authorization": {"Bearer from-the-policy"}})
	if values := got.Values("Authorization"); len(values) != 1 || values[0] != "Bearer from-the-policy" {
		t.Errorf("Authorization = %q, want only %q", values, "Bearer from-the-policy")
	}
}

func TestTransport_AddsTheContextHeadersTheRequestLacks(t *testing.T) {
	pip := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{
		Headers: func(context.Context) http.Header {
			return http.Header{"x-request-id": {"from-context"}, "traceparent": {"00-trace-span-01"}}
		},
	})
	got := send(t, rt, pip, http.Header{"X-Request-Id": {"from-the-policy"}})
	if v := got.Values("X-Request-Id"); len(v) != 1 || v[0] != "from-the-policy" {
		t.Errorf("X-Request-Id = %q, want only %q", v, "from-the-policy")
	}
	if v := got.Get("Traceparent"); v != "00-trace-span-01" {
		t.Errorf("Traceparent = %q, want %q", v, "00-trace-span-01")
	}
}

type requestKey struct{}

func TestTransport_TakesTheHeadersFromTheRequestsContext(t *testing.T) {
	pip := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{
		Headers: func(ctx context.Context) http.Header {
			id, _ := ctx.Value(requestKey{}).(string)
			return http.Header{"X-Request-Id": {id}}
		},
	})
	req, err := http.NewRequestWithContext(context.WithValue(context.Background(), requestKey{}, "req-42"), http.MethodGet, pip.srv.URL+"/pip", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_ = resp.Body.Close()
	if got := pip.requests()[0].Get("X-Request-Id"); got != "req-42" {
		t.Errorf("X-Request-Id = %q, want %q from the request's context", got, "req-42")
	}
}

func TestTransport_LeavesTheCallersRequestUnchanged(t *testing.T) {
	pip := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{
		Authorize: AllowHosts("http://" + hostOf(t, pip)),
		Headers:   func(context.Context) http.Header { return http.Header{"Traceparent": {"00-trace-span-01"}} },
	})
	req, err := http.NewRequest(http.MethodGet, pip.srv.URL+"/pip", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_ = resp.Body.Close()
	if len(req.Header) != 0 {
		t.Errorf("caller's request headers after RoundTrip = %v, want none", req.Header)
	}
}

// closeRecorder is a request body that records whether it was closed.
type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

// The two controls of TestTransport_FailsWithoutAToken: a request that
// needs no token is sent while the token function returns "".
func TestTransport_SendsWithoutATokenARequestThatNeedsNone(t *testing.T) {
	pip := newRecorder(t, nil)
	other := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken(""), TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})
	tests := []struct {
		name   string
		target *recorder
		header http.Header
		want   string
	}{
		{"request to a host that gets no token", other, nil, ""},
		{"request with its own Authorization", pip, http.Header{"Authorization": {"Bearer from-the-policy"}}, "Bearer from-the-policy"},
	}
	for _, tt := range tests {
		if got := send(t, rt, tt.target, tt.header).Get("Authorization"); got != tt.want {
			t.Errorf("%s: Authorization = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// The token function returns "" on its first call and a token on the next,
// as a FileSource does once its file appears.
func TestTransport_AsksForTheTokenOnEveryRequest(t *testing.T) {
	pip := newRecorder(t, nil)
	calls := 0
	token := func() string {
		calls++
		if calls == 1 {
			return ""
		}
		return "tok-2"
	}
	rt := NewTransport(http.DefaultTransport, token, TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})
	req, err := http.NewRequest(http.MethodGet, pip.srv.URL+"/pip", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); !errors.Is(err, ErrNoToken) {
		t.Fatalf("first RoundTrip() error = %v, want %v", err, ErrNoToken)
	}
	if got := send(t, rt, pip, nil).Get("Authorization"); got != "Bearer tok-2" {
		t.Errorf("Authorization on the second request = %q, want %q", got, "Bearer tok-2")
	}
}

func TestTransport_FailsWithoutAToken(t *testing.T) {
	pip := newRecorder(t, nil)
	rt := NewTransport(http.DefaultTransport, staticToken(""), TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})
	body := &closeRecorder{Reader: strings.NewReader("{}")}
	req, err := http.NewRequest(http.MethodPost, pip.srv.URL+"/pip", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); !errors.Is(err, ErrNoToken) {
		t.Errorf("RoundTrip() error = %v, want %v", err, ErrNoToken)
	}
	if n := len(pip.requests()); n != 0 {
		t.Errorf("requests the PIP received = %d, want 0", n)
	}
	if !body.closed {
		t.Errorf("request body was not closed")
	}
}

// NoToken runs only for a request that needs the token and finds none; the
// other rows are the controls.
func TestTransport_ReportsARequestThatFindsNoToken(t *testing.T) {
	pip := newRecorder(t, nil)
	other := newRecorder(t, nil)
	tests := []struct {
		name   string
		token  string
		target *recorder
		want   int
	}{
		{"authorized host without a token", "", pip, 1},
		{"authorized host with a token", "tok-1", pip, 0},
		{"host without the token", "", other, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			rt := NewTransport(http.DefaultTransport, staticToken(tt.token), TransportOptions{
				Authorize: AllowHosts("http://" + hostOf(t, pip)),
				NoToken:   func() { calls++ },
			})
			req, err := http.NewRequest(http.MethodGet, tt.target.srv.URL+"/pip", nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp, err := rt.RoundTrip(req); err == nil {
				_ = resp.Body.Close()
			}
			if calls != tt.want {
				t.Errorf("NoToken calls = %d, want %d", calls, tt.want)
			}
		})
	}
}

// The request the PIP received is the control: it shows the token reached
// the first host.
func TestTransport_DoesNotCarryTheTokenThroughARedirectToAnotherHost(t *testing.T) {
	elsewhere := newRecorder(t, nil)
	pip := newRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.srv.URL+"/landing", http.StatusFound)
	})
	client := &http.Client{Transport: NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{Authorize: AllowHosts("http://" + hostOf(t, pip))})}
	resp, err := client.Get(pip.srv.URL + "/pip")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	_ = resp.Body.Close()
	if len(pip.requests()) != 1 || len(elsewhere.requests()) != 1 {
		t.Fatalf("requests at the PIP = %d and after the redirect = %d, want 1 and 1", len(pip.requests()), len(elsewhere.requests()))
	}
	if got := pip.requests()[0].Get("Authorization"); got != "Bearer tok-1" {
		t.Errorf("Authorization at the PIP = %q, want %q", got, "Bearer tok-1")
	}
	if got := elsewhere.requests()[0].Get("Authorization"); got != "" {
		t.Errorf("Authorization after the redirect = %q, want none", got)
	}
}

func TestAllowHosts(t *testing.T) {
	allow := AllowHosts("pip", "Entitlements:8443", "secure:443", "::1", "[fe80::2]", "[fe80::1]:9000", "http://legacy", "http://plain:8080", "http://plain80:80", "https://explicit")
	tests := []struct {
		url  string
		want bool
	}{
		{"https://pip:8080/x", true},
		{"https://PIP/x", true},
		{"http://pip/x", false},
		{"https://entitlements:8443/x", true},
		{"https://ENTITLEMENTS:8443/x", true},
		{"https://entitlements:8080/x", false},
		{"http://entitlements:8443/x", false},
		{"https://secure/x", true},
		{"https://secure:8443/x", false},
		{"https://[::1]:8080/x", true},
		{"https://[fe80::2]:7000/x", true},
		{"https://[fe80::1]:9000/x", true},
		{"https://[fe80::1]:9001/x", false},
		{"http://legacy:9000/x", true},
		{"https://legacy/x", false},
		{"http://plain:8080/x", true},
		{"http://plain/x", false},
		{"http://plain80/x", true},
		{"https://explicit/x", true},
		{"http://explicit/x", false},
		{"ftp://pip/x", false},
		{"https://pip.evil.example/x", false},
		{"https://evilpip/x", false},
	}
	for _, tt := range tests {
		u, err := url.Parse(tt.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := allow(u); got != tt.want {
			t.Errorf("AllowHosts(...)(%s) = %t, want %t", tt.url, got, tt.want)
		}
	}
}

// Both servers listen on 127.0.0.1, and the entry names that host without
// a port, so only the scheme tells them apart. The request the TLS server
// received is the control: it shows the token reached the first host.
func TestTransport_DoesNotCarryTheTokenThroughARedirectToPlainHTTP(t *testing.T) {
	plain := newRecorder(t, nil)
	var mu sync.Mutex
	var secureAuth string
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		secureAuth = r.Header.Get("Authorization")
		mu.Unlock()
		http.Redirect(w, r, plain.srv.URL+"/landing", http.StatusFound)
	}))
	t.Cleanup(secure.Close)
	client := &http.Client{Transport: NewTransport(secure.Client().Transport, staticToken("tok-1"), TransportOptions{Authorize: AllowHosts("127.0.0.1")})}
	resp, err := client.Get(secure.URL + "/pip")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	_ = resp.Body.Close()
	if len(plain.requests()) != 1 {
		t.Fatalf("requests after the redirect = %d, want 1", len(plain.requests()))
	}
	mu.Lock()
	defer mu.Unlock()
	if secureAuth != "Bearer tok-1" {
		t.Errorf("Authorization at the TLS server = %q, want %q", secureAuth, "Bearer tok-1")
	}
	if got := plain.requests()[0].Get("Authorization"); got != "" {
		t.Errorf("Authorization after the redirect to plain HTTP = %q, want none", got)
	}
}

// A 401 says the service refused the token only when the transport added
// it; the other rows are the controls.
func TestTransport_ReportsA401ToARequestThatCarriedTheToken(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		authorize bool
		header    http.Header
		want      int
	}{
		{"401 to a request with the token", http.StatusUnauthorized, true, nil, 1},
		{"200 to a request with the token", http.StatusOK, true, nil, 0},
		{"403 to a request with the token", http.StatusForbidden, true, nil, 0},
		{"401 to a request with its own Authorization", http.StatusUnauthorized, true,
			http.Header{"Authorization": {"Bearer caller"}}, 0},
		{"401 to a host that gets no token", http.StatusUnauthorized, false, nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(tt.status) })
			var reports int
			rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{
				Authorize:    func(*url.URL) bool { return tt.authorize },
				Unauthorized: func() { reports++ },
			})
			send(t, rt, target, tt.header)
			if reports != tt.want {
				t.Errorf("Unauthorized calls = %d, want %d", reports, tt.want)
			}
			if got := len(target.requests()); got != 1 {
				t.Errorf("requests at the service = %d, want 1: a refused request is not sent again", got)
			}
		})
	}
}

// roundTripFunc adapts a function to [http.RoundTripper].
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// For a request that carried the token and got no response, RoundTrip
// returns the error of the base transport, and Unauthorized does not run.
func TestTransport_ReturnsTheErrorOfARequestThatCarriedTheToken(t *testing.T) {
	refused := errors.New("connection refused")
	base := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, refused })
	var reports int
	rt := NewTransport(base, staticToken("tok-1"), TransportOptions{
		Authorize:    func(*url.URL) bool { return true },
		Unauthorized: func() { reports++ },
	})
	req, err := http.NewRequest(http.MethodGet, "http://pip.invalid/pip", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := rt.RoundTrip(req)
	if !errors.Is(err, refused) {
		t.Errorf("RoundTrip() error = %v, want %v", err, refused)
	}
	if resp != nil {
		t.Errorf("RoundTrip() response = %v, want nil", resp)
	}
	if reports != 0 {
		t.Errorf("Unauthorized calls = %d, want 0", reports)
	}
}

func TestTransport_ReturnsA401WhenUnauthorizedIsNil(t *testing.T) {
	target := newRecorder(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	rt := NewTransport(http.DefaultTransport, staticToken("tok-1"), TransportOptions{Authorize: func(*url.URL) bool { return true }})
	req, err := http.NewRequest(http.MethodGet, target.srv.URL+"/pip", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("RoundTrip() status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
