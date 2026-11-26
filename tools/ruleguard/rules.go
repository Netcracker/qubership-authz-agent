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

//go:build ruleguard

// Package gorules holds the ruleguard rules of the repository, which
// golangci-lint runs through gocritic (see .github/linters/.golangci.yml). A
// known violation is suppressed where it stands with
// //nolint:gocritic // <finding>: <what is wrong>, and nolintlint fails the
// build once the line no longer violates the rule.
package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// recordOutsideItsConstructor flags a regogen.Record built, or a field of one
// assigned, anywhere but in project.go, where record checks the state of an operand against the domain
// of its kind. A Record built elsewhere would reach the module with a state
// the generated leaves have no answer for.
func recordOutsideItsConstructor(m dsl.Matcher) {
	m.Import("authz-agent/internal/regogen")
	m.Match(`Record{$*_}`).
		Where(m.File().PkgPath.Matches(`(^|/)internal/regogen$`) &&
			!m.File().Name.Matches(`^project\.go$`) && !m.File().Name.Matches(`_test\.go$`)).
		Report(`a Record is built only by record in project.go, which checks the state against the domain of the operand's kind`)
	m.Match(`$x.$f = $_`).
		Where((m["x"].Type.Is(`regogen.Record`) || m["x"].Type.Is(`*regogen.Record`)) &&
			m.File().PkgPath.Matches(`(^|/)internal/regogen$`) &&
			!m.File().Name.Matches(`^project\.go$`) && !m.File().Name.Matches(`_test\.go$`)).
		Report(`a Record is built only by record in project.go, which checks the state against the domain of the operand's kind`)
}

// textAsIdentity flags the text a value renders for people (String, Dump,
// fmt's %v) used as its identity: hashed, used as a map key, or compared
// with ==. Such text may drop a difference the code reads elsewhere, such as
// nil against an empty map, or print two values of different types alike,
// such as "true" and true. The rule matches the expression in place: text
// first stored in a variable, or rendered with %s, passes.
func textAsIdentity(m dsl.Matcher) {
	m.Import("hash")
	m.Import("bytes")
	m.Import("strings")
	m.Import("io")
	m.Match(`$sum([]byte(fmt.Sprint($*_)))`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["sum"].Text.Matches(`^[a-z0-9]+\.Sum`)).
		Report(`fmt renders text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`$sum([]byte(fmt.Sprintf($s, $*_)))`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["s"].Text.Matches(`%[-+# 0-9.]*v`) &&
			m["sum"].Text.Matches(`^[a-z0-9]+\.Sum`)).
		Report(`fmt renders text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`$h.Write([]byte(fmt.Sprint($*_)))`, `fmt.Fprint($h, $*_)`, `fmt.Fprintln($h, $*_)`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["h"].Type.Implements("hash.Hash")).
		Report(`fmt renders text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`$h.Write([]byte(fmt.Sprintf($s, $*_)))`, `fmt.Fprintf($h, $s, $*_)`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["s"].Text.Matches(`%[-+# 0-9.]*v`) &&
			m["h"].Type.Implements("hash.Hash")).
		Report(`fmt renders text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`io.WriteString($h, $x.$f())`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`) &&
			m["h"].Type.Implements("hash.Hash")).
		Report(`$x.$f() is text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`map[$k]$v{$*_, $x.$f(): $_, $*_}`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`)).
		Report(`$x.$f() is text for people; key the map by a comparable value or a canonical encoding`)
	m.Match(`$sum([]byte($x.$f()))`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`) &&
			m["sum"].Text.Matches(`^[a-z0-9]+\.Sum`)).
		Report(`$x.$f() is text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`$h.Write([]byte($x.$f()))`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`) &&
			m["h"].Type.Implements("hash.Hash")).
		Report(`$x.$f() is text for people; hash a canonical encoding that keeps every field instead`)
	m.Match(`$mp[$x.$f()]`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`) &&
			m["mp"].Type.Is(`map[$_]$_`)).
		Report(`$x.$f() is text for people; key the map by a comparable value or a canonical encoding`)
	m.Match(`$mp[fmt.Sprint($*_)]`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["mp"].Type.Is(`map[$_]$_`)).
		Report(`fmt renders text for people; key the map by a comparable value or a canonical encoding`)
	m.Match(`$mp[fmt.Sprintf($s, $*_)]`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["mp"].Type.Is(`map[$_]$_`) && m["s"].Text.Matches(`%[-+# 0-9.]*v`)).
		Report(`fmt renders text for people; key the map by a comparable value or a canonical encoding`)
	m.Match(`$x.$f() == $_`, `$_ == $x.$f()`, `$x.$f() != $_`, `$_ != $x.$f()`).
		Where(m["f"].Text.Matches(`^(String|Dump)$`) && !m.File().Name.Matches(`_test\.go$`) &&
			!m["x"].Type.Is(`*bytes.Buffer`) && !m["x"].Type.Is(`bytes.Buffer`) &&
			!m["x"].Type.Is(`*strings.Builder`) && !m["x"].Type.Is(`strings.Builder`) &&
			!m["x"].Type.Underlying().Is(`string`)).
		Report(`$x.$f() is text for people; compare the values, not what they print`)
	m.Match(`fmt.Sprint($*_) == $_`, `$_ == fmt.Sprint($*_)`, `fmt.Sprint($*_) != $_`, `$_ != fmt.Sprint($*_)`).
		Where(!m.File().Name.Matches(`_test\.go$`)).
		Report(`fmt renders text for people; compare the values, not what they print`)
	m.Match(`fmt.Sprintf($s, $*_) == $_`, `$_ == fmt.Sprintf($s, $*_)`,
		`fmt.Sprintf($s, $*_) != $_`, `$_ != fmt.Sprintf($s, $*_)`).
		Where(!m.File().Name.Matches(`_test\.go$`) && m["s"].Text.Matches(`%[-+# 0-9.]*v`)).
		Report(`fmt renders text for people; compare the values, not what they print`)
}

// discardedResponse flags a test that calls a helper returning the response
// of a request and drops it: the test cannot fail on the status or the body
// of that request, so a setup step that failed goes unnoticed.
func discardedResponse(m dsl.Matcher) {
	m.Import("net/http")
	m.Import("net/http/httptest")
	m.Match(`$f($*_)`).
		Where(m.File().Name.Matches(`_test\.go$`) && m["$$"].Node.Parent().Is(`ExprStmt`) &&
			(m["$$"].Type.Is(`*httptest.ResponseRecorder`) || m["$$"].Type.Is(`*http.Response`))).
		Report(`the response of $f is dropped; check its status, or have the helper check it`)
}

// pathTextOutsideJSONPath flags code outside internal/jsonpath that reads a
// bracket step of a jsonPath, such as $['key'], from the text of the path.
// The package decides what such a step selects; a second reading drifts from
// it.
func pathTextOutsideJSONPath(m dsl.Matcher) {
	m.Match(`regexp.MustCompile($s)`, `regexp.Compile($s)`).
		Where(!m.File().PkgPath.Matches(`(^|/)internal/jsonpath$`) && m["s"].Text.Matches(`\\\[\s*'`)).
		Report(`a jsonPath bracket step is read by internal/jsonpath only`)
	m.Match(`strings.HasPrefix($_, $s)`, `strings.TrimPrefix($_, $s)`, `strings.CutPrefix($_, $s)`,
		`strings.Index($_, $s)`, `strings.Contains($_, $s)`, `strings.Cut($_, $s)`, `strings.Split($_, $s)`,
		`strings.SplitN($_, $s, $_)`).
		Where(!m.File().PkgPath.Matches(`(^|/)internal/jsonpath$`) && m["s"].Text.Matches("^[\"`]\\$?\\['")).
		Report(`a jsonPath bracket step is read by internal/jsonpath only`)
}
