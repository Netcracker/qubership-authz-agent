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

// substitutionRule was written for the interpreter substitution cases, which
// are now data under testdata/cases/interpreter, and round 10 still builds a Go
// case with it.

// substitutionRule builds an ALLOW rule on LIST, keyed list, that names
// placeholder in all five predicate fields: rsql, sql, mongodb, querydsl, and
// a custom predicate whose parameter p names it.
func substitutionRule(b regularBuilder, placeholder string) map[string]any {
	rule := b.rule("list", "operation == 'LIST'", "true", "ALLOW", map[string]string{
		"rsqlPredicate":    "a==${" + placeholder + "}",
		"sqlPredicate":     "a=${" + placeholder + "}",
		"mongodbPredicate": `{ "a": ${` + placeholder + `} }`,
		"predicate":        "${resourceType}.a.eq(${" + placeholder + "})",
	})
	rule["customPredicate"] = map[string]any{
		"predicate": "a:${p}",
		"params":    map[string]any{"p": placeholder},
	}
	return rule
}
