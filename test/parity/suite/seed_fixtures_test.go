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

// The tenant packs are seeded only by the tenant-scoped cases, once per tenant,
// into the same domain name.
//
//go:embed testdata/fixtures/tenants/a/*.json
var embeddedTenantAFixtures embed.FS

//go:embed testdata/fixtures/tenants/b/*.json
var embeddedTenantBFixtures embed.FS

var (
	smokeFixtureFS   fs.FS = mustSubFS(embeddedSmokeFixtures, "testdata/fixtures/smoke")
	mainFixtureFS    fs.FS = mustSubFS(embeddedMainFixtures, "testdata/fixtures")
	tenantAFixtureFS fs.FS = mustSubFS(embeddedTenantAFixtures, "testdata/fixtures/tenants/a")
	tenantBFixtureFS fs.FS = mustSubFS(embeddedTenantBFixtures, "testdata/fixtures/tenants/b")
)

func mustSubFS(root embed.FS, subdir string) fs.FS {
	sub, err := fs.Sub(root, subdir)
	if err != nil {
		panic(err)
	}
	return sub
}
