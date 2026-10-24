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
// suite asserts against. Each struct mirrors the JSON the legacy service
// sends or accepts, field by field.
package model

// ApiVersionResponse is the body of GET /api-version. The legacy server emits
// integer major, minor and supportedMajors; the Go struct uses int to preserve
// that byte shape per D-V item 11.
type ApiVersionResponse struct {
	Specs []ApiVersionSpec `json:"specs"`
}

// ApiVersionSpec is one entry of ApiVersionResponse.Specs.
type ApiVersionSpec struct {
	SpecRootUrl     string `json:"specRootUrl"`
	Major           int    `json:"major"`
	Minor           int    `json:"minor"`
	SupportedMajors []int  `json:"supportedMajors"`
}
