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

// Package model holds the legacy access-control wire DTO structs the parity
// suite asserts against. Each struct mirrors a legacy Java Jackson DTO
// field-by-field; file-level comments cite the legacy source class.
package model

// ApiVersionResponse mirrors the legacy server's
// com.netcracker.security.authorization.abac.controller.apiversion.ApiVersionResponse.
// The legacy server emits integer-typed major/minor/supportedMajors
// (ApiVersionSpec.java:12-17); the Go struct uses int to preserve that
// byte shape per D-V item 11 of the parity suite handover.
type ApiVersionResponse struct {
	Specs []ApiVersionSpec `json:"specs"`
}

// ApiVersionSpec mirrors
// com.netcracker.security.authorization.abac.controller.apiversion.ApiVersionSpec.
type ApiVersionSpec struct {
	SpecRootUrl     string `json:"specRootUrl"`
	Major           int    `json:"major"`
	Minor           int    `json:"minor"`
	SupportedMajors []int  `json:"supportedMajors"`
}
