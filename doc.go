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

// Package authzagent is the root of the authz-agent module. The binaries
// live under components/ and the shared packages under internal/; this file
// exists so the module root is a valid Go package for tools that analyze
// the current directory rather than ./... (notably golangci-lint as invoked
// by super-linter's GO_MODULES check).
package authzagent
