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

import "testing"

// regularCaseLists are the functions that build regular cases. A new list is
// added here, or its ids are checked by nothing.
var regularCaseLists = map[string]func() []regularCase{
	"regularPolicySetCases":    regularPolicySetCases,
	"translatorPolicySetCases": translatorPolicySetCases,
	"translatorFailedPIPCases": translatorFailedPIPCases,
	"deadFormRegularCases":     deadFormRegularCases,
	"combiningCases":           combiningCases,
	"interpreterFilterCases":   interpreterFilterCases,
	"iterateBindingCases":      iterateBindingCases,
	"setTargetCases":           setTargetCases,
}

// Every regular case has an id of its own across every list, and every request of
// a case a name of its own. The golden path is regular/<id>/<request>, so two
// cases with one id would compare against each other's goldens, and their sets
// would replace each other on the stand under one resource type.
func TestRegularCaseIDsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for list, build := range regularCaseLists {
		for _, tc := range build() {
			if earlier, dup := seen[tc.id]; dup {
				t.Errorf("regular case id %q is built by %s and by %s", tc.id, earlier, list)
			}
			seen[tc.id] = list
			names := map[string]struct{}{}
			for _, req := range tc.requests {
				if _, dup := names[req.name]; dup {
					t.Errorf("regular case %q names two requests %q", tc.id, req.name)
				}
				names[req.name] = struct{}{}
			}
		}
	}
}
