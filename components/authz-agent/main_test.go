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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"

	"authz-agent/components/authz-agent/internal/authn"
	"authz-agent/components/authz-agent/internal/decisionlog"
	"authz-agent/components/authz-agent/internal/engine"
	"authz-agent/components/authz-agent/internal/pull"
)

type quiet struct{}

func (quiet) Infof(string, ...any) {}
func (quiet) Warnf(string, ...any) {}

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

// TestLoadAuthSecret: the trimmed token of the file becomes
// data.opa_auth_secret, and an empty file stores nothing.
func TestLoadAuthSecret(t *testing.T) {
	eng := newEngine(t)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(" s3cret \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadAuthSecret(context.Background(), eng, file); err != nil {
		t.Fatalf("loadAuthSecret() = %v", err)
	}
	if value, ok, _ := eng.Get(context.Background(), []string{"opa_auth_secret"}); !ok || value != "s3cret" {
		t.Errorf("data.opa_auth_secret = %v, %v; want s3cret", value, ok)
	}
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := newEngine(t)
	if err := loadAuthSecret(context.Background(), other, empty); err != nil {
		t.Fatalf("loadAuthSecret() on an empty file = %v", err)
	}
	if _, ok, _ := other.Get(context.Background(), []string{"opa_auth_secret"}); ok {
		t.Error("an empty file must store no secret")
	}
	if err := loadAuthSecret(context.Background(), other, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file must be an error")
	}
}

// TestServeUntilShutdown_LogsADecisionMadeWhileTheSurfacesDrain: the
// shutdown waits for the handlers still running, and every one of them
// produces a decision, so the queue is read until the last has returned.
// While the logger shared the signal context with the surfaces it stopped
// reading at the signal, and this decision reached nothing.
func TestServeUntilShutdown_LogsADecisionMadeWhileTheSurfacesDrain(t *testing.T) {
	store := decisionlog.NewStore(filepath.Join(t.TempDir(), "decision-logs.jsonl"))
	logs := decisionlog.New(decisionlog.Config{Store: store, FlushInterval: 5 * time.Millisecond}, nil)

	handling := make(chan struct{})
	app := fiber.New()
	app.Get("/slow", func(c *fiber.Ctx) error {
		close(handling)
		// Still in the handler when the shutdown starts, as a bulk check of
		// 3000 resources or one waiting on a PIP would be.
		time.Sleep(200 * time.Millisecond)
		logs.Log(decisionlog.Event{DecisionID: "served-while-draining"})
		return c.SendString("ok")
	})
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- serveUntilShutdown(ctx, cancel, logs, []surface{{"public", app, socket}}) }()
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
	case <-time.After(10 * time.Second):
		t.Fatal("serveUntilShutdown has not returned ten seconds after the shutdown")
	}
	<-requested

	data, err := store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "served-while-draining") {
		t.Errorf("the store holds %q, want the decision of the request the shutdown waited for", data)
	}
}
