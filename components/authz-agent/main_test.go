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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/engine"
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

// The agent runs as a child process of this test binary, which calls main
// when AUTHZ_AGENT_TEST_RUN_MAIN is set.
func TestStart_StopsOnAnInvalidValueAndNamesIt(t *testing.T) {
	if os.Getenv("AUTHZ_AGENT_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	for _, tt := range []struct{ name, level string }{
		{"at the default log level", ""},
		{"at the log level fatal", "fatal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			agent := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStart_StopsOnAnInvalidValueAndNamesIt$")
			agent.Env = append(os.Environ(), "AUTHZ_AGENT_TEST_RUN_MAIN=1", "LOGGING_LEVEL_ROOT="+tt.level,
				"AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s", "AUTHZ_HTTP_ADDR=127.0.0.1:0", "AUTHZ_PUBLIC_ADDR=127.0.0.1:0",
				"AUTHZ_TRUSTED_PROVIDERS_FILE=")
			out, err := agent.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Errorf("the agent with AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s ended with %v, want exit status 1", err)
			}
			want := `configuration: AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036`
			if !strings.Contains(string(out), want) {
				t.Errorf("the agent's output lacks %q:\n%s", want, out)
			}
		})
	}
}

// TestGet: a variable set to the empty string is returned as the empty
// string, where configloader alone would fall back to the default; an
// unset variable takes the default, and a set one is returned as set.
func TestGet(t *testing.T) {
	t.Setenv("AUTHZ_TRUSTED_PROVIDERS_FILE", "")
	if got := get("authz.trusted.providers.file", authn.DefaultFile); got != "" {
		t.Errorf("get() with the variable empty = %q, want empty", got)
	}
	if got := get("authz.trusted.providers.unset", "fallback"); got != "fallback" {
		t.Errorf("get() with the variable unset = %q, want the fallback", got)
	}
	t.Setenv("AUTHZ_TRUSTED_PROVIDERS_FILE", "/p.json")
	// init read the environment before t.Setenv; a fresh Init sees the value.
	configloader.Init(configloader.EnvPropertySource())
	if got := get("authz.trusted.providers.file", authn.DefaultFile); got != "/p.json" {
		t.Errorf("get() with the variable set = %q, want /p.json", got)
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
