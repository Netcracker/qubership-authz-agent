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
	"embed"
	"io/fs"
)

//go:embed testdata/fixtures/smoke/*.json
var embeddedSmokeFixtures embed.FS

//go:embed testdata/fixtures/smoke/*.json testdata/fixtures/policies/suite/*.json testdata/fixtures/policies/regular/*.json
var embeddedMainFixtures embed.FS

// embeddedAuthzAgentFixtures is the main pack plus the row 30 request-args
// pack. Legacy access-control rejects the row 30 PIPs, whose headers field is
// a JSON object where access-control expects a string.
//
//go:embed testdata/fixtures/smoke/*.json testdata/fixtures/policies/suite/*.json testdata/fixtures/policies/regular/*.json testdata/fixtures/requestargs/*.json
var embeddedAuthzAgentFixtures embed.FS

// The tenant packs are seeded only by the tenant-scoped cases, once per tenant,
// into the same domain name.
//
//go:embed testdata/fixtures/tenants/a/*.json
var embeddedTenantAFixtures embed.FS

//go:embed testdata/fixtures/tenants/b/*.json
var embeddedTenantBFixtures embed.FS

var (
	smokeFixtureFS      fs.FS = mustSubFS(embeddedSmokeFixtures, "testdata/fixtures/smoke")
	mainFixtureFS       fs.FS = mustSubFS(embeddedMainFixtures, "testdata/fixtures")
	authzAgentFixtureFS fs.FS = mustSubFS(embeddedAuthzAgentFixtures, "testdata/fixtures")
	tenantAFixtureFS    fs.FS = mustSubFS(embeddedTenantAFixtures, "testdata/fixtures/tenants/a")
	tenantBFixtureFS    fs.FS = mustSubFS(embeddedTenantBFixtures, "testdata/fixtures/tenants/b")
)

// mainFixturesFor returns the fixture tree SetupSuite seeds after the smoke
// phase. Each seed replaces the whole domain, so the row 30 pack travels in the
// same tree as the main pack rather than in a second seed call.
func mainFixturesFor(profile string) fs.FS {
	if isAuthzAgentProfile(profile) {
		return authzAgentFixtureFS
	}
	return mainFixtureFS
}

func mustSubFS(root embed.FS, subdir string) fs.FS {
	sub, err := fs.Sub(root, subdir)
	if err != nil {
		panic(err)
	}
	return sub
}
