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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSource_ReadsTheTokenAtStart(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, "  first\n")
	s := NewFileSource(path, time.Hour, nil)
	runInBackground(t, s.Run)
	select {
	case <-s.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out after 5s waiting for Ready")
	}
	if got := s.Token(); got != "first" {
		t.Errorf("Token() = %q, want %q", got, "first")
	}
}

// The kubelet publishes a projected token as a symlink into a directory it
// swaps whole, so the path keeps its name while it starts to point at a new
// file.
func TestFileSource_FollowsATokenTheKubeletSwaps(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"..2026_10_15_a": "first", "..2026_10_15_b": "second"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(dir, name, "token"), content)
	}
	mustSymlink(t, "..2026_10_15_a", filepath.Join(dir, "..data"))
	mustSymlink(t, filepath.Join("..data", "token"), filepath.Join(dir, "token"))
	s := NewFileSource(filepath.Join(dir, "token"), 10*time.Millisecond, nil)
	runInBackground(t, s.Run)
	waitFor(t, "the first token", func() bool { return s.Token() == "first" })

	mustSymlink(t, "..2026_10_15_b", filepath.Join(dir, "..data_tmp"))
	if err := os.Rename(filepath.Join(dir, "..data_tmp"), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the swapped token", func() bool { return s.Token() == "second" })
}

// The tests that call read directly do so because a read that changes
// nothing is not observable through Run.
func TestFileSource_WaitsForAMissingFile(t *testing.T) {
	path := inTempDir(t, "token")
	s := NewFileSource(path, time.Hour, nil)
	s.read()
	writeFile(t, path, "first")
	s.read()
	if got := s.Token(); got != "first" {
		t.Errorf("Token() after the file appeared = %q, want %q", got, "first")
	}
}

func TestFileSource_KeepsTheTokenWhenTheFileEmpties(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, "first")
	s := NewFileSource(path, time.Hour, nil)
	s.read()
	writeFile(t, path, " \n")
	s.read()
	if got := s.Token(); got != "first" {
		t.Errorf("Token() after the file emptied = %q, want %q", got, "first")
	}
}

func TestFileSource_KeepsTheTokenWhenTheFileGoesAway(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, "first")
	s := NewFileSource(path, time.Hour, nil)
	s.read()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.read()
	if got := s.Token(); got != "first" {
		t.Errorf("Token() after the file went away = %q, want %q", got, "first")
	}
}

// A ticker with no interval panics, so Run reaching its first read shows
// that the default interval applies.
func TestFileSource_RunsWithTheDefaultIntervalForZero(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, "first")
	s := NewFileSource(path, 0, nil)
	runInBackground(t, s.Run)
	waitFor(t, "the token", func() bool { return s.Token() == "first" })
}

func TestFileSource_NeverLogsTheToken(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, "tok-secret-1")
	log := &recordingLogger{}
	s := NewFileSource(path, time.Hour, log)
	s.read()
	for _, m := range log.all() {
		if strings.Contains(m, "tok-secret-1") {
			t.Errorf("log message %q carries the token", m)
		}
	}
	if len(log.all()) == 0 {
		t.Errorf("read logged nothing, want the line it writes for a new token")
	}
}

func TestFileSource_IsNotReadyWithAnEmptyFile(t *testing.T) {
	path := inTempDir(t, "token")
	writeFile(t, path, " \n")
	s := NewFileSource(path, time.Hour, nil)
	s.read()
	select {
	case <-s.Ready():
		t.Errorf("Ready is closed with an empty file, want it open")
	default:
	}
	if got := s.Token(); got != "" {
		t.Errorf("Token() = %q, want %q", got, "")
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
