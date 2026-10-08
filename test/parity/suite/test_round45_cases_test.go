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

// Round 45 asks how a sequence case can keep its PAP state away from every
// other case. TestRound45TenantFreshCases writes domain policies and the sets
// of an externalId in the tenant parity-pap-r45-fresh, which no fixture
// creates, decides there and in the default tenant, and empties what it wrote.
// TestRound45TenantDomainCases tries the fallback: a domain of its own in the
// default tenant, read before the first write and after the cleanup, and a
// write the PAP refuses, to show whether the refusal leaves part of its body
// behind. The cases are data under testdata/cases/round45, and each case's
// about field says what it asks.

// TestRound45TenantFreshCases runs round45/tenant-fresh.json.
func (s *ParitySuite) TestRound45TenantFreshCases() {
	s.runCaseFile("round45/tenant-fresh.json")
}

// TestRound45TenantDomainCases runs round45/tenant-domain.json.
func (s *ParitySuite) TestRound45TenantDomainCases() {
	s.runCaseFile("round45/tenant-domain.json")
}
