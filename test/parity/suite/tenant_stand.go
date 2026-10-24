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

package paritysuite

// TenantStand is a stand with two tenants, each with its own identity realm.
// Tenant A is the stand's default tenant. The M2M token and the end-user client
// credentials come from the base [Config]; only the realm and the users differ.
type TenantStand struct {
	A TenantRealm
	B TenantRealm
}

// TenantRealm is one tenant of a [TenantStand].
type TenantRealm struct {
	// ID is the tenant identifier the PAP stores and tenant_id carries.
	ID string
	// IDPBaseURL is the realm base URL, ending in /realms/<realm>.
	IDPBaseURL string
	// User holds ROLE_MT_READER.
	User string
	// AdminUser holds ROLE_MT_ADMIN.
	AdminUser string
}

// Configured reports whether both tenants have an identifier and a realm.
func (ts TenantStand) Configured() bool {
	return ts.A.ID != "" && ts.A.IDPBaseURL != "" && ts.B.ID != "" && ts.B.IDPBaseURL != ""
}

// loadTenantStand reads PARITY_MT_TENANT_{A,B}_{ID,IDP_BASE_URL,USER,ADMIN_USER}.
// The users default to mt-a, mt-a-admin, mt-b, and mt-b-admin.
func loadTenantStand() TenantStand {
	return TenantStand{
		A: loadTenantRealm("A", "mt-a"),
		B: loadTenantRealm("B", "mt-b"),
	}
}

func loadTenantRealm(letter, user string) TenantRealm {
	prefix := "PARITY_MT_TENANT_" + letter + "_"
	return TenantRealm{
		ID:         envOr(prefix+"ID", ""),
		IDPBaseURL: envOr(prefix+"IDP_BASE_URL", ""),
		User:       envOr(prefix+"USER", user),
		AdminUser:  envOr(prefix+"ADMIN_USER", user+"-admin"),
	}
}
