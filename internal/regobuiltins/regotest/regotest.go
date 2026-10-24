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

// Package regotest runs Rego tests that call the built-in functions of
// [regobuiltins] with OPA's test runner. It is a separate package so that
// production code does not link the runner.
package regotest

import (
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/tester"

	"authz-agent/internal/regobuiltins"
)

// NewCompiler returns a compiler that knows the built-in functions.
func NewCompiler() *ast.Compiler {
	return ast.NewCompiler().WithCapabilities(regobuiltins.Capabilities())
}

// Builtins returns the built-in functions in the form
// [tester.Runner.AddCustomBuiltins] takes.
func Builtins() []*tester.Builtin {
	all := regobuiltins.All()
	out := make([]*tester.Builtin, len(all))
	for i, b := range all {
		out[i] = &tester.Builtin{Decl: b.Decl, Func: b.Option}
	}
	return out
}

// NewRunner returns a test runner whose compiler and queries know the
// built-in functions.
func NewRunner() *tester.Runner {
	return tester.NewRunner().SetCompiler(NewCompiler()).AddCustomBuiltins(Builtins())
}
