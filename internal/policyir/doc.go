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

// Package policyir is the intermediate representation of the policies of one
// tenant: policy sets, policies, rules, simplified policies, their targets and
// conditions, and the PIP declarations. [FromRegular] builds one [Tree] per
// tenant from the v3 configuration export, and the Rego generator reads it.
//
// The representation covers every form the PAP accepts, including forms no
// tenant uses today. A form the agent cannot execute yet stays in the tree as an
// [Unsupported] atom or operand, and [Tree.Unsupported] lists it together with
// the structural forms the agent cannot execute, so the generator can reject the
// tenant's candidate snapshot as a whole instead of dropping the form.
//
// The tree carries no semantics. What a leaf evaluates to, what an absent
// algorithm or effect means, and how a profile of the specification differs from
// the legacy service are the specification's tables; the tree keeps such values
// as written, with an explicit zero value for "absent". Children keep their
// source order, so a trace and a filter can be built in that order.
//
// The legacy service applies customizations before it exports, and a frontend
// drops the top-level sets whose status keeps them out; every other status stays
// in the tree as written, for the profile to read. Nodes are built with struct
// literals or constructors, and [NewTree] checks the whole tree against every
// invariant documented here. The fields stay exported and NewTree does not copy them, so
// the guarantee holds for a tree that nobody changes after NewTree returns it.
package policyir
