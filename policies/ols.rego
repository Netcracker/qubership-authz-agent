# Copyright 2024-2026 Netcracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package ols

import rego.v1

# resource_type and operation are expected to be pre-uppercased by the caller.
evaluate(resource_type, operation, subject_roles) := {
  "allow": true,
  "roles": matched_roles
} if {
  role_list := data.policies.ols[resource_type][operation]
  matched_roles := [role |
    role := role_list[_]
    subject_roles[role]
  ]
  count(matched_roles) > 0
} else := {"allow": false, "roles": []}
