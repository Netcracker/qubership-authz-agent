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

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/m2m"
	"authz-agent/components/authz-agent/internal/pull"
)

type quiet struct{}

func (quiet) Debugf(string, ...any) {}
func (quiet) Infof(string, ...any)  {}
func (quiet) Warnf(string, ...any)  {}

func newEngine(t *testing.T) *engine.Engine {
	t.Helper()
	eng, err := engine.New(engine.Options{Modules: map[string]string{"authorize.rego": "package authorize\n\nimport rego.v1\n\nallowed := true\n"}})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// TestReport: the report is healthy but not loaded while the policies have
// not loaded, unhealthy with the trusted providers' reason when their
// bootstrap failed, and healthy and loaded once both are in order; a
// disabled pull counts as loaded.
func TestReport(t *testing.T) {
	eng := newEngine(t)
	idle := pull.New(pull.Config{}, eng, nil, quiet{})
	if r := report(nil, idle); !r.Healthy || r.Loaded {
		t.Errorf("report before any pull = %+v, want healthy and not loaded", r)
	}
	idle.Run(context.Background())
	if r := report(nil, idle); !r.Healthy || !r.Loaded || r.Message != "" || r.Conversion != nil {
		t.Errorf("report with the pull disabled = %+v, want healthy and loaded without counts", r)
	}
	providers := authn.New(authn.Config{File: filepath.Join(t.TempDir(), "absent.json")}, eng, quiet{})
	providers.Bootstrap(context.Background())
	r := report(providers, idle)
	if r.Healthy || r.Message != "trusted providers configuration is invalid" || r.ConfigError == "" {
		t.Errorf("report with a broken providers file = %+v, want unhealthy with the configuration error", r)
	}
	file := filepath.Join(t.TempDir(), "providers.json")
	if err := os.WriteFile(file, []byte(`{"providers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	providers = authn.New(authn.Config{File: file}, eng, quiet{})
	providers.Bootstrap(context.Background())
	if r := report(providers, idle); !r.Healthy || !r.Loaded {
		t.Errorf("report with no providers and the pull disabled = %+v, want healthy and loaded", r)
	}
}

// TestNewPuller_ReturnsWhileTheTokenSourceRunsUntilCtxEnds: the token source
// is observed through data.m2m.bearerToken. While ctx lasts, a change of the
// file reaches it within one WatchInterval; a change made after ctx ended
// does not.
func TestNewPuller_ReturnsWhileTheTokenSourceRunsUntilCtxEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		eng := newEngine(t)
		file := filepath.Join(t.TempDir(), "token")
		writeToken(t, file, "first")
		cfg := config{M2M: m2m.Config{TokenFile: file, WatchInterval: time.Second}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		returned := make(chan struct{})
		go func() {
			newPuller(ctx, cfg, eng)
			close(returned)
		}()
		synctest.Wait()
		select {
		case <-returned:
		default:
			t.Fatal("newPuller has not returned with the token source running")
		}
		if got := m2mToken(t, eng); got != "first" {
			t.Errorf("data.m2m.bearerToken after newPuller = %q, want %q", got, "first")
		}

		writeToken(t, file, "second")
		time.Sleep(time.Second)
		synctest.Wait()
		if got := m2mToken(t, eng); got != "second" {
			t.Errorf("data.m2m.bearerToken one interval after the file changed = %q, want %q", got, "second")
		}

		cancel()
		synctest.Wait()
		writeToken(t, file, "third")
		time.Sleep(time.Second)
		synctest.Wait()
		if got := m2mToken(t, eng); got != "second" {
			t.Errorf("data.m2m.bearerToken one interval after ctx ended and the file changed = %q, want %q", got, "second")
		}
	})
}

// TestNewPuller_FetchesWithTheTokenFromTheFile: the first pull of
// [pull.Puller.Run] waits up to 15 seconds for the source's first token, so
// the test needs no wait of its own. The 20 seconds the test allows outlast
// that wait, so a puller whose source never delivers a token fails on the
// Authorization header rather than on the time limit.
func TestNewPuller_FetchesWithTheTokenFromTheFile(t *testing.T) {
	authorization := make(chan string, 1)
	policySource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/access/v3/config/policySets" {
			select {
			case authorization <- r.Header.Get("Authorization"):
			default:
			}
		}
		_, _ = w.Write([]byte("[]"))
	}))
	defer policySource.Close()
	file := filepath.Join(t.TempDir(), "token")
	writeToken(t, file, "agent-token")
	cfg := config{
		Pull: pull.Config{SourceURL: policySource.URL, Interval: time.Hour},
		M2M:  m2m.Config{TokenFile: file},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	puller := newPuller(ctx, cfg, newEngine(t))
	go puller.Run(ctx)
	select {
	case got := <-authorization:
		if got != "Bearer agent-token" {
			t.Errorf("Authorization of the policy sets request = %q, want %q", got, "Bearer agent-token")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no request for the policy sets reached the policy source within 20 seconds")
	}
}

// writeToken writes token to file, replacing what the file held.
func writeToken(t *testing.T, file, token string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
}

// m2mToken returns data.m2m.bearerToken from eng, or "" while it is
// undefined.
func m2mToken(t *testing.T, eng *engine.Engine) string {
	t.Helper()
	value, _, err := eng.Eval(context.Background(), []string{"m2m", "bearerToken"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := value.(string)
	return token
}

// TestGet: a variable set to the empty string is returned as the empty
// string, where configloader alone would fall back to the default; an
// unset variable takes the default, and a set one is returned as set.
func TestGet(t *testing.T) {
	t.Setenv("AUTHZ_TENANT_MANAGER_URL", "")
	if got := get("authz.tenant.manager.url", "http://tenant-manager:8080"); got != "" {
		t.Errorf("get() with the variable empty = %q, want empty", got)
	}
	if got := get("authz.tenant.manager.unset", "fallback"); got != "fallback" {
		t.Errorf("get() with the variable unset = %q, want the fallback", got)
	}
	t.Setenv("AUTHZ_TENANT_MANAGER_URL", "http://tm:1")
	// init read the environment before t.Setenv; a fresh Init sees the value.
	configloader.Init(configloader.EnvPropertySource())
	if got := get("authz.tenant.manager.url", "http://tenant-manager:8080"); got != "http://tm:1" {
		t.Errorf("get() with the variable set = %q, want http://tm:1", got)
	}
}

// TestServeUntilShutdown_WaitsForARequestInItsHandler: the shutdown gives a
// handler still running five seconds to return, so a rolling restart does not
// cut off a check that finishes within them.
func TestServeUntilShutdown_WaitsForARequestInItsHandler(t *testing.T) {
	var finished atomic.Bool
	handling := make(chan struct{})
	app := fiber.New()
	app.Get("/slow", func(c *fiber.Ctx) error {
		close(handling)
		// Still in the handler when the shutdown starts, as a bulk check of
		// 3000 resources or one waiting on a PIP would be.
		time.Sleep(200 * time.Millisecond)
		finished.Store(true)
		return c.SendString("ok")
	})
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- serveUntilShutdown(ctx, cancel, []surface{{"public", app, socket}}) }()
	requested := make(chan struct{})
	go func() {
		defer close(requested)
		resp, err := http.Get("http://" + socket.Addr().String() + "/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	<-handling
	cancel()
	select {
	case failed := <-done:
		if failed {
			t.Error("serveUntilShutdown() = true, want the shutdown rather than a failed surface")
		}
		if !finished.Load() {
			t.Error("serveUntilShutdown returned with the request still in its handler")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown has not returned ten seconds after the shutdown")
	}
	<-requested
}

// freeAddress returns a loopback address that no socket holds when it
// returns.
func freeAddress(t *testing.T) string {
	t.Helper()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

// busyAddress returns a loopback address that a socket holds until the test
// ends.
func busyAddress(t *testing.T) string {
	t.Helper()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket.Addr().String()
}

// TestServe_FailsOnAnAddressInUse: an address already in use fails the start
// before either surface serves, whichever surface it belongs to, and the
// other address is free again afterwards.
func TestServe_FailsOnAnAddressInUse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		publicBusy bool
	}{
		{"the public address is in use", true},
		{"the internal address is in use", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{PublicAddr: freeAddress(t), Addr: busyAddress(t)}
			other := cfg.PublicAddr
			if tc.publicBusy {
				cfg.PublicAddr, cfg.Addr = cfg.Addr, cfg.PublicAddr
				other = cfg.Addr
			}
			// A serve that went on to serve would return only at the
			// deadline, and report the shutdown rather than the failure.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if !serve(ctx, cancel, cfg, 1, fiber.New(), fiber.New()) {
				t.Errorf("serve(public %s, internal %s) = false, want the failed start", cfg.PublicAddr, cfg.Addr)
			}
			socket, err := net.Listen("tcp", other)
			if err != nil {
				t.Fatalf("binding %s after the failed start: %v, want the address free", other, err)
			}
			_ = socket.Close()
		})
	}
}

// TestServe_ServesBothSurfacesUntilShutdown: each app answers on the address
// of its own surface, and the end of ctx is a shutdown, not a failure.
func TestServe_ServesBothSurfacesUntilShutdown(t *testing.T) {
	apps := map[string]*fiber.App{"public": fiber.New(), "internal": fiber.New()}
	for name, app := range apps {
		app.Get("/surface", func(c *fiber.Ctx) error { return c.SendString(name) })
	}
	cfg := config{PublicAddr: freeAddress(t), Addr: freeAddress(t)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() {
		done <- serve(ctx, cancel, cfg, 1, apps["public"], apps["internal"])
	}()

	for name, address := range map[string]string{"public": cfg.PublicAddr, "internal": cfg.Addr} {
		if got := waitForBody(t, "http://"+address+"/surface"); got != name {
			t.Errorf("GET http://%s/surface = %q, want %q", address, got, name)
		}
	}
	cancel()
	select {
	case failed := <-done:
		if failed {
			t.Error("serve() = true, want the shutdown rather than a failed surface")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve has not returned ten seconds after the shutdown")
	}
}

// waitForBody polls url until it answers 200 and returns the body. It fails
// the test with the last error when five seconds pass without an answer.
func waitForBody(t *testing.T, url string) string {
	t.Helper()
	var last error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		resp, err := http.Get(url)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK {
			return string(body)
		}
		last = fmt.Errorf("status %d, read error %v", resp.StatusCode, err)
	}
	t.Fatalf("GET %s did not answer 200 within five seconds; last: %v", url, last)
	return ""
}
