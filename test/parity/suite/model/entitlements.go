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

package model

// GetDirectUserEntitlementsResponse mirrors the EA v3 direct-user response
// consumed by EntitlementsPipServiceImpl#getUserEntitlementsMappingV3 on the
// legacy side. The payload shape is verified against
// access-control-java-libs/.../movetoapi/entitlements/model/*.java and the EA
// integration-test fixture expectedGetDirectUserEntitlementResponse.json.
type GetDirectUserEntitlementsResponse struct {
	Entitlements          []Entitlement `json:"entitlements"`
	Definitions           []Definition  `json:"definitions"`
	DefinitionUpdatedWhen string        `json:"definitionUpdatedWhen,omitempty"`
}

// Entitlement groups references by resourceType on the EA wire.
type Entitlement struct {
	ResourceType string                 `json:"resourceType"`
	References   []EntitlementReference `json:"references"`
}

// EntitlementReference names one entitlement bucket and carries the resources
// that belong to it.
type EntitlementReference struct {
	Name      string              `json:"name"`
	Resources []EntitlementTarget `json:"resources"`
}

// EntitlementTarget is one EA resource id entry.
type EntitlementTarget struct {
	ResourceID string `json:"resourceId"`
	ValidFrom  string `json:"validFrom,omitempty"`
	ValidTill  string `json:"validTill,omitempty"`
}

// Definition mirrors the optional EA definition metadata. The parity suite's
// entitlements rows do not need it, but the field is present on the real wire
// and the mock should stay structurally accurate.
type Definition struct {
	ResourceType string                `json:"resourceType"`
	References   []DefinitionReference `json:"references"`
}

// DefinitionReference is one named entitlement definition inside a resource
// type bucket.
type DefinitionReference struct {
	Name string `json:"name"`
}
