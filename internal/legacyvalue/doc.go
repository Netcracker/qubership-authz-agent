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

// Package legacyvalue reads an operand value of the legacy policy language the
// way the legacy Java service reads it, and builds the value record that
// generated Rego compares instead of raw JSON.
//
// Rego cannot compare raw JSON the way the legacy service does: it has no
// Double.toString, no Java String.valueOf of a list or an object, and no
// BigDecimal, and it compares two fractions that both end in zeros as float64.
// A [Record] therefore carries every comparison key that generated code needs,
// computed here once per value rather than once per comparison.
//
// A value is a [authz-agent/internal/jsonvalue.Value]. The Java text of an
// object depends on the order of its members, which
// [authz-agent/internal/jsonvalue.Decode] keeps and
// [authz-agent/internal/jsonvalue.FromAST] cannot, because an OPA object
// iterates its keys in sorted order.
package legacyvalue
