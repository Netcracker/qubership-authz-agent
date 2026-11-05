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

//go:build integration

package paritysuite

import (
	"context"
	"io/fs"
	"slices"
	"testing"
)

// recordingSeeder records the calls BeforeTest makes, as "seed DOMAIN" and
// "wipe DOMAIN".
type recordingSeeder struct {
	calls []string
}

func (r *recordingSeeder) WipeDomain(_ context.Context, domain string) error {
	r.calls = append(r.calls, "wipe "+domain)
	return nil
}

func (r *recordingSeeder) SeedDomain(_ context.Context, domain string, _ fs.FS) error {
	r.calls = append(r.calls, "seed "+domain)
	return nil
}

// TestBeforeTest_SeedsTheMainFixturesOnlyAroundTestRowTests: SetupSuite
// leaves the main domain empty, so BeforeTest seeds it before the first
// TestRow test of a run, wipes it before the first test of another kind that
// follows, and does nothing while the kind stays the same.
func TestBeforeTest_SeedsTheMainFixturesOnlyAroundTestRowTests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tests []string
		want  []string
	}{
		{"no TestRow test", []string{"TestInterpreterA", "TestRound10A", "TestTenantA"}, nil},
		{"TestRow tests only", []string{"TestRow02A", "TestRow02B", "TestRow30A"}, []string{"seed PARITY"}},
		{"TestRow tests between others", []string{"TestRound10A", "TestRow02A", "TestRow02B", "TestTenantA", "TestTranslatorA"},
			[]string{"seed PARITY", "wipe PARITY"}},
		{"TestRow tests split by another kind", []string{"TestRow02A", "TestRound10A", "TestRow30A"},
			[]string{"seed PARITY", "wipe PARITY", "seed PARITY"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seeder := &recordingSeeder{}
			s := &ParitySuite{cfg: Config{DomainName: "PARITY", Profile: "legacy"}, seeder: seeder}
			s.SetT(t)
			for _, name := range tc.tests {
				s.BeforeTest("ParitySuite", name)
			}
			if !slices.Equal(seeder.calls, tc.want) {
				t.Errorf("BeforeTest over %q made calls %q, want %q", tc.tests, seeder.calls, tc.want)
			}
		})
	}
}
