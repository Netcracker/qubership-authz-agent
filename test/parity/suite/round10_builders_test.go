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

import "strings"

// round10ResourceType is the resource type of the round 10 case keyed key. The
// round's cases that are data under testdata/cases/round10 derive the same
// type from their resourceTypePrefix, and the cases still written in Go build
// it here.
func round10ResourceType(key string) string {
	return "PARITY_SUITE_R10_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}
