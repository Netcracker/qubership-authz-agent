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
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netcracker/qubership-core-lib-go/v3/logging"
)

// reported keeps the level and the text of every line a run wrote.
type reported struct{ lines []string }

func (r *reported) record(level, format string, args ...any) {
	r.lines = append(r.lines, level+": "+fmt.Sprintf(format, args...))
}

func (r *reported) Infof(format string, args ...any)  { r.record("info", format, args...) }
func (r *reported) Warnf(format string, args ...any)  { r.record("warn", format, args...) }
func (r *reported) Errorf(format string, args ...any) { r.record("error", format, args...) }

// reported keeps a line at every level, so it reports the most verbose level
// and ignores a new one.
func (r *reported) GetLevel() logging.Lvl { return logging.LvlDebug }
func (r *reported) SetLevel(logging.Lvl)  {}

// contains reports whether any line at level holds substring.
func (r *reported) contains(level, substring string) bool {
	for _, line := range r.lines {
		if strings.HasPrefix(line, level+": ") && strings.Contains(line, substring) {
			return true
		}
	}
	return false
}

// records swaps the command's logger for the run of one test.
func records(t *testing.T) *reported {
	t.Helper()
	rec := &reported{}
	previous := logger
	logger = rec
	t.Cleanup(func() { logger = previous })
	return rec
}

// The stub takes policies from anyone who can reach it, so every start says
// so: whoever reads the log of a namespace it was installed in is the person
// who has to decide whether that is acceptable there. A start that keeps the
// policies in memory says that too, because the next restart serves nothing.
func TestBuild_ReportsWhatTheRunIs(t *testing.T) {
	// The directory carries a domain from an earlier run, which the start
	// names: a restart that silently served nothing would look the same in
	// the log as one that loaded everything.
	seeded := t.TempDir()
	if err := os.WriteFile(filepath.Join(seeded, policiesFilePrefix+"BSS.json"), []byte(bssPolicies), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	for name, dataDir := range map[string]string{"with a data directory": seeded, "with none": ""} {
		t.Run(name, func(t *testing.T) {
			rec := records(t)
			mux, addr, err := build(dataDir, "18090", defaultTenant, "false")
			if err != nil {
				t.Fatalf("build(%q) = %v", dataDir, err)
			}
			assertServes(t, mux, addr)
			assertReportsTheRun(t, rec, dataDir)
		})
	}
}

// assertServes fails unless build returned routes and the address its port
// makes.
func assertServes(t *testing.T, mux *http.ServeMux, addr string) {
	t.Helper()
	if mux == nil {
		t.Fatal("build returned no routes")
	}
	if addr != "0.0.0.0:18090" {
		t.Errorf("build listens on %q, want 0.0.0.0:18090", addr)
	}
}

// assertReportsTheRun fails unless the start reported that the upload API is
// open, and where the policies are kept or that they are kept nowhere.
func assertReportsTheRun(t *testing.T, rec *reported, dataDir string) {
	t.Helper()
	if !rec.contains("warn", "unauthenticated") {
		t.Errorf("the run reported %v, want a warning that the API is unauthenticated", rec.lines)
	}
	if dataDir == "" {
		if !rec.contains("warn", "persistence disabled") {
			t.Errorf("the run reported %v, want a warning that nothing is persisted", rec.lines)
		}
		return
	}
	if !rec.contains("info", dataDir) {
		t.Errorf("the run reported %v, want the directory the policies are kept in", rec.lines)
	}
	if !rec.contains("info", "BSS") {
		t.Errorf("the run reported %v, want the domain it loaded from that directory", rec.lines)
	}
}

// A data directory the stub cannot write to is a failed start, not a run that
// drops every upload: build names the store and main exits on it.
func TestBuild_RefusesADataDirectoryItCannotWrite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	records(t)
	dir := filepath.Join(t.TempDir(), "read-only")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, _, err := build(dir, "18090", defaultTenant, "false")
	if err == nil {
		t.Fatal("build over an unwritable data directory = nil, want an error")
	}
	if !strings.Contains(err.Error(), "store") {
		t.Errorf("build reported %q, want an error naming the store", err)
	}
}

// The command runs as a child process of this test binary, which calls main
// when AUTHZ_POLICY_ADMIN_TEST_RUN_MAIN is 1. Every child gets a port that a
// socket of this test holds, so a start that gets past the store fails on the
// listener instead of serving.
func TestStart_LogsWhyItFailed(t *testing.T) {
	if os.Getenv("AUTHZ_POLICY_ADMIN_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	socket, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	_, port, _ := net.SplitHostPort(socket.Addr().String())

	for _, tt := range []struct {
		name    string
		level   string
		dataDir string
		want    string
	}{
		{"a data directory that is a file at the level fatal", "fatal", file, "store: create data dir " + file + " "},
		{"a data directory that is a file at the level info", "info", file, "store: create data dir " + file + " "},
		{"a port in use at the level fatal", "fatal", "", "listening on 0.0.0.0:" + port + ": "},
		{"a port in use at the level info", "info", "", "listening on 0.0.0.0:" + port + ": "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStart_LogsWhyItFailed$")
			command.Env = append(childEnvironment(), "AUTHZ_POLICY_ADMIN_TEST_RUN_MAIN=1", "LOGGING_LEVEL_ROOT="+tt.level,
				"AUTHZ_POLICY_ADMIN_DATA_DIR="+tt.dataDir, "AUTHZ_POLICY_ADMIN_PORT="+port)
			out, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Errorf("authz-policy-admin at LOGGING_LEVEL_ROOT=%s ended with %v, want exit status 1", tt.level, err)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("the output of authz-policy-admin at LOGGING_LEVEL_ROOT=%s lacks %q:\n%s", tt.level, tt.want, out)
			}
		})
	}
}

// childEnvironment is the environment of this test process without every
// variable whose name starts with log.level or logging.level once folded as
// configloader folds it, to lower case with dots for underscores. Such a
// variable can set a level the platform logger reads, as LOG_LEVEL does, or
// hide LOGGING_LEVEL_ROOT from it, as LOGGING_LEVEL_ROOT_X does.
func childEnvironment() []string {
	var kept []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		key := strings.ReplaceAll(strings.ToLower(name), "_", ".")
		if strings.HasPrefix(key, "log.level") || strings.HasPrefix(key, "logging.level") {
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

// The routes build serves are the stub's own: the export the agent pulls
// answers before anything has been uploaded.
func TestBuild_ServesTheExport(t *testing.T) {
	records(t)
	mux, _, err := build(t.TempDir(), "18090", defaultTenant, "false")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	do(t, mux, http.MethodGet, "/access/v3/config/policySets", "", http.StatusOK)
}

// The chart always sets the port, and `docker run` of this image without one
// has to keep working, so an unset and an empty variable both take the
// fallback.
func TestEnvOr(t *testing.T) {
	const key = "AUTHZ_POLICY_ADMIN_PORT"
	for name, set := range map[string]string{"a value": "19000", "an empty value": ""} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(key, set)
			want := set
			if set == "" {
				want = "18090"
			}
			if got := envOr(key, "18090"); got != want {
				t.Errorf("envOr(%q) = %q with the variable set to %q, want %q", key, got, set, want)
			}
		})
	}
	t.Run("the variable is not set", func(t *testing.T) {
		if got := envOr("AUTHZ_POLICY_ADMIN_PORT_UNSET", "18090"); got != "18090" {
			t.Errorf("envOr on an unset variable = %q, want the fallback 18090", got)
		}
	})
}

// AUTHZ_POLICY_ADMIN_REQUIRE_DECLARED_PIPS reaches the policy upload, and a
// value that is no boolean stops the start.
func TestBuild_RequiresDeclaredPIPsWhenAsked(t *testing.T) {
	records(t)
	const body = `[{"component":"BILLING","resourceType":"INVOICE","operation":"READ","roles":["R"],` +
		`"condition":"subject.dept == 'x'"}]`
	for value, want := range map[string]int{"true": http.StatusBadRequest, "false": http.StatusOK} {
		mux, _, err := build("", "18090", defaultTenant, value)
		if err != nil {
			t.Fatalf("build(%q) = %v", value, err)
		}
		if rec := serve(mux, http.MethodPut, policiesPath+"billing", body, ""); rec.Code != want {
			t.Errorf("with %q, PUT of a policy reading an undeclared PIP = %d %s, want %d", value, rec.Code, rec.Body, want)
		}
	}
	if _, _, err := build("", "18090", defaultTenant, "sometimes"); err == nil ||
		!strings.Contains(err.Error(), "AUTHZ_POLICY_ADMIN_REQUIRE_DECLARED_PIPS") {
		t.Errorf(`build with "sometimes" = %v, want an error naming AUTHZ_POLICY_ADMIN_REQUIRE_DECLARED_PIPS`, err)
	}
}
