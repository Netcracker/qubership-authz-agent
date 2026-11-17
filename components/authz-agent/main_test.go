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
	"github.com/netcracker/qubership-core-lib-go/v3/logging"

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
// when AUTHZ_AGENT_TEST_RUN_MAIN is 1. The child reads no trusted providers
// file and no token file, so that only the value under test stops it.
func TestStart_StopsAndNamesTheVariable(t *testing.T) {
	if os.Getenv("AUTHZ_AGENT_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	busy := busyAddress(t)
	for _, tt := range []struct {
		name  string
		env   []string
		level string
		want  string
	}{
		{"an invalid value at the default log level", []string{"AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s"}, "",
			`configuration: AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036`},
		{"an invalid value at the log level fatal", []string{"AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s"}, "fatal",
			`configuration: AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036`},
		{"a root log level under log_level", []string{"log_level=debug"}, "",
			`configuration: log_level="debug": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`},
		{"an invalid value beside a root log level under log_level", []string{"AUTHZ_PAP_CLIENT_PULL_INTERVAL=2s", "log_level=debug"}, "",
			`configuration: AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036; ` +
				`log_level="debug": expected no variable of this name, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`},
		{"a public address in use at the default log level", []string{"AUTHZ_PUBLIC_ADDR=" + busy}, "",
			`public listener on AUTHZ_PUBLIC_ADDR="` + busy + `": `},
		{"a public address in use at the log level fatal", []string{"AUTHZ_PUBLIC_ADDR=" + busy}, "fatal",
			`public listener on AUTHZ_PUBLIC_ADDR="` + busy + `": `},
		{"an internal address in use at the log level fatal", []string{"AUTHZ_HTTP_ADDR=" + busy}, "fatal",
			`internal listener on AUTHZ_HTTP_ADDR="` + busy + `": `},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			agent := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStart_StopsAndNamesTheVariable$")
			agent.Env = append(childEnvironment(), "AUTHZ_AGENT_TEST_RUN_MAIN=1", "LOGGING_LEVEL_ROOT="+tt.level,
				"AUTHZ_HTTP_ADDR=127.0.0.1:0", "AUTHZ_PUBLIC_ADDR=127.0.0.1:0",
				"AUTHZ_TRUSTED_PROVIDERS_FILE=", "AUTHZ_PAP_CLIENT_TOKEN_FILE=")
			agent.Env = append(agent.Env, tt.env...)
			out, err := agent.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Errorf("the agent with %v ended with %v, want exit status 1", tt.env, err)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("the agent's output lacks %q:\n%s", tt.want, out)
			}
		})
	}
}

// childEnvironment is the environment of this test process without the
// variables that the agent or the platform logger can read: every variable
// whose name starts with authz., log.level, or logging.level once folded as
// configloader folds it, to lower case with dots for underscores.
func childEnvironment() []string {
	var kept []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		key := strings.ReplaceAll(strings.ToLower(name), "_", ".")
		if strings.HasPrefix(key, "authz.") || strings.HasPrefix(key, "log.level") || strings.HasPrefix(key, "logging.level") {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

func TestLogStop_RaisesOnlyTheLevelFatal(t *testing.T) {
	saved := logger.GetLevel()
	t.Cleanup(func() { logger.SetLevel(saved) })
	for _, tt := range []struct {
		name      string
		level     logging.Lvl
		wantLevel logging.Lvl
	}{
		{"fatal is raised to error", logging.LvlCrit, logging.LvlError},
		{"error stays error", logging.LvlError, logging.LvlError},
		{"debug stays debug", logging.LvlDebug, logging.LvlDebug},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logger.SetLevel(tt.level)
			logStop("logStop test line")
			if got := logger.GetLevel(); got != tt.wantLevel {
				t.Errorf("logger level after logStop() at %v = %v, want %v", tt.level, got, tt.wantLevel)
			}
		})
	}
}

func TestGet(t *testing.T) {
	t.Run("an empty variable is returned empty", func(t *testing.T) {
		t.Setenv("AUTHZ_TRUSTED_PROVIDERS_FILE", "")
		if got := get("authz.trusted.providers.file", authn.DefaultFile); got != "" {
			t.Errorf("get() with AUTHZ_TRUSTED_PROVIDERS_FILE empty = %q, want empty", got)
		}
	})
	t.Run("an unset variable takes the fallback", func(t *testing.T) {
		if got := get("authz.agent.test.unset", "fallback"); got != "fallback" {
			t.Errorf("get() with AUTHZ_AGENT_TEST_UNSET unset = %q, want the fallback", got)
		}
	})
	t.Run("a set variable is returned as set", func(t *testing.T) {
		t.Setenv("AUTHZ_TRUSTED_PROVIDERS_FILE", "/p.json")
		if got := get("authz.trusted.providers.file", authn.DefaultFile); got != "/p.json" {
			t.Errorf("get() with AUTHZ_TRUSTED_PROVIDERS_FILE=/p.json = %q, want /p.json", got)
		}
	})
}

// Where one variable's name adds an underscore and a suffix to another's, as
// LOG_LEVEL_PACKAGE_AUTHZ-AGENT does to LOG_LEVEL, configloader, which main
// initializes from the environment, nests the longer one under the key of the
// shorter one. Each test initializes it again after setting the variables, so
// that a get that read through configloader would see them.
func TestLoadConfig_RefusesAValueBesideAVariableThatExtendsItsName(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"LOG_LEVEL alone", map[string]string{"LOG_LEVEL": "debug"},
			`LOG_LEVEL="debug": expected no value, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`},
		{"LOG_LEVEL beside a package log level", map[string]string{"LOG_LEVEL": "debug", "LOG_LEVEL_PACKAGE_AUTHZ-AGENT": "info"},
			`LOG_LEVEL="debug": expected no value, since the agent reads the root log level from LOGGING_LEVEL_ROOT alone`},
		{"a pull interval beside a longer variable", map[string]string{"AUTHZ_PAP_CLIENT_PULL_INTERVAL": "2s", "AUTHZ_PAP_CLIENT_PULL_INTERVAL_X": "1"},
			`AUTHZ_PAP_CLIENT_PULL_INTERVAL="2s": expected an integer number of seconds from 0 to 9223372036`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { configloader.Init(configloader.EnvPropertySource()) })
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			configloader.Init(configloader.EnvPropertySource())
			if _, err := loadConfig(get); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("loadConfig(get) with %v in the environment = %v, want an error with %q", tt.env, err, tt.want)
			}
		})
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
