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
	"net/http"
)

// TestRow01ApiVersion drives parity-contract row 1 (GET /api-version, PSUITE-1-m2m).
// Unauthenticated per SpringApiVersionService.java:36-61 — the probe runs
// before interceptor selection, so no Authorization / Incoming-Token header
// is sent. Golden asserts the integer byte shape from D-V item 11.
func (s *ParitySuite) TestRow01ApiVersion() {
	ctx := context.Background()

	status, decoded, err := HelperApiVersion(ctx, s.cfg)
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, status)

	if err := s.comparator.Compare(PSUITE_ROW_1_API_VERSION, "m2m", &decoded); err != nil {
		s.T().Errorf("%v", err)
	}
}
