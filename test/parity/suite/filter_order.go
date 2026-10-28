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

package paritysuite

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"authz-agent/test/parity/suite/model"
)

// Access-control joins the predicates of the rules that apply to a filter request
// in an order that differs from one run to the next, at every level of the
// expression: the terms of one OR, the terms of one AND, and the bracketed groups
// of nested sets and of simplified policies. The functions here rewrite each
// filter dialect into a form in which the terms of every operator and the
// elements of every list are sorted, so that two answers that differ in that
// order alone compare equal. A list here is also a list of values the stand
// substitutes from a PIP answer, which it writes as an IN list, as the
// arguments of an eq call, or as a comma-separated tail of a comparison. The
// arguments of an SQL function and of an RSQL comparison other than =in= and
// =out= keep their order: they come from a predicate text the policy sets,
// which the stand copies as written, and there the order carries meaning. The
// form is for comparison only; the golden on disk keeps the text the stand
// answered.
//
// The canonical text is not the dialect's own syntax: separators are rejoined
// without the stand's spacing, and a chain of method calls is written back in
// the same chain order after sorting. Both sides of a comparison pass through
// the same rewrite, so only the difference between them matters.

// normalizeFilterOrder applies the order rewrite to every dialect of a filter
// answer, and returns v unchanged for any other golden type.
func normalizeFilterOrder(v any) any {
	switch typed := v.(type) {
	case *model.OldFilterEvaluationResult:
		clone := *typed
		normalizeOldFilterResultOrder(&clone)
		return &clone
	case *model.FilterOutcome:
		clone := *typed
		normalizeOldFilterResultOrder(&clone.Result)
		return &clone
	case *model.FilterV2Outcome:
		clone := *typed
		normalizeOldFilterResultOrder(&clone.Result)
		return &clone
	case *model.FilterResponse:
		clone := *typed
		clone.FilterCondition = clone.FilterCondition.Map(canonicalMethodChain)
		clone.MongodbFilterCondition = clone.MongodbFilterCondition.Map(infixCanon(mongodbSeparators))
		clone.RsqlFilterCondition = clone.RsqlFilterCondition.Map(infixCanon(rsqlDialect))
		clone.SqlFilterCondition = clone.SqlFilterCondition.Map(infixCanon(sqlDialect))
		clone.CustomFilterCondition = canonicalJSON(clone.CustomFilterCondition)
		return &clone
	default:
		return v
	}
}

func normalizeOldFilterResultOrder(r *model.OldFilterEvaluationResult) {
	r.FilterCondition = r.FilterCondition.Map(canonicalMethodChain)
	r.MongodbFilterCondition = r.MongodbFilterCondition.Map(infixCanon(mongodbSeparators))
	r.RsqlFilterCondition = r.RsqlFilterCondition.Map(infixCanon(rsqlDialect))
	r.SqlFilterCondition = r.SqlFilterCondition.Map(infixCanon(sqlDialect))
	r.CustomFilterCondition = canonicalJSON(r.CustomFilterCondition)
}

// An infixDialect is what canonicalInfix needs to know of one infix filter
// dialect: the separators of its operators, from the loosest-binding to the
// tightest, and which bracket groups hold arguments whose order carries
// meaning. At each bracket level the text is split at the first operator that
// occurs outside brackets and quotes, and that operator decides the terms of
// the level.
type infixDialect struct {
	operators []string
	// orderedArguments reports whether the bracket group that opens at the end
	// of prefix holds arguments that keep their order. The comma-separated
	// elements of any other group are sorted.
	orderedArguments func(prefix string) bool
}

var (
	// rsqlBracketedComparison matches the text before the bracketed operand of
	// an RSQL comparison, and captures the name of the comparison.
	rsqlBracketedComparison = regexp.MustCompile(`=([A-Za-z]*)=\($`)
	// sqlFunctionCall matches the text before the arguments of an SQL function,
	// a name followed by the bracket with no space, and captures the name.
	sqlFunctionCall = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\($`)

	// The comma of RSQL is its OR. A bracketed operand of =in= or =out= is a
	// set of values; that of any other comparison, such as =between=, keeps
	// its order.
	rsqlDialect = infixDialect{
		operators: []string{",", ";"},
		orderedArguments: func(prefix string) bool {
			m := rsqlBracketedComparison.FindStringSubmatch(prefix)
			return m != nil && m[1] != "in" && m[1] != "out"
		},
	}
	// The comma of SQL separates the elements of an IN list, and of a list of
	// values the stand substitutes after a comparison, as in a='a', 'b'.
	sqlDialect = infixDialect{
		operators: []string{" OR ", " AND ", ","},
		orderedArguments: func(prefix string) bool {
			m := sqlFunctionCall.FindStringSubmatch(prefix)
			if m == nil {
				return false
			}
			switch strings.ToUpper(m[1]) {
			case "IN", "NOT", "AND", "OR":
				return false
			}
			return true
		},
	}
	// mongodbSeparators split the members of an object and the elements of an
	// array of a mongodbFilterCondition.
	mongodbSeparators = infixDialect{
		operators:        []string{","},
		orderedArguments: func(string) bool { return false },
	}
	// methodArgumentSeparators split the arguments of one call in the method
	// chain dialect, such as the elements of an in list.
	methodArgumentSeparators = []string{","}
)

// canonicalInfix sorts the terms of every operator in an infix expression. At
// each bracket level the text is split at the first operator of d that occurs
// outside brackets and quotes; the parts are canonicalized in turn, trimmed,
// sorted, and rejoined with that operator. A level that no operator splits
// keeps its text, with every bracketed group inside it canonicalized; the
// comma-separated arguments of a group for which d.orderedArguments holds are
// canonicalized and kept in their order.
func canonicalInfix(expr string, d infixDialect) string {
	for _, sep := range d.operators {
		parts := splitOutsideBrackets(expr, sep)
		if len(parts) < 2 {
			continue
		}
		return joinTerms(parts, sep, true, func(part string) string { return canonicalInfix(part, d) })
	}
	return rewriteBracketGroups(expr, func(prefix, inner string) string {
		if d.orderedArguments(prefix) {
			return joinTerms(splitOutsideBrackets(inner, ","), ",", false, func(part string) string { return canonicalInfix(part, d) })
		}
		return canonicalInfix(strings.TrimSpace(inner), d)
	})
}

// infixCanon returns canonicalInfix for the dialect d, the form
// [model.FilterText.Map] applies to a dialect's text.
func infixCanon(d infixDialect) func(string) string {
	return func(expr string) string { return canonicalInfix(expr, d) }
}

// joinTerms trims every part, rewrites it with canonicalize unless that is nil,
// sorts the parts when sorted is set, and joins them with sep.
func joinTerms(parts []string, sep string, sorted bool, canonicalize func(string) string) string {
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
		if canonicalize != nil {
			parts[i] = canonicalize(parts[i])
		}
	}
	if sorted {
		sort.Strings(parts)
	}
	return strings.Join(parts, sep)
}

// canonicalMethodChain sorts the operands of a chain of .and( ) or .or( ) calls,
// the form of filterCondition: first.and(second).and(third). The chain is split
// at every .and( and .or( outside brackets and quotes. Each operand is stripped
// of the brackets that enclose it whole, since the stand brackets the first
// operand of a chain and not the others, and is canonicalized in turn. When
// every call in the chain is the same method the operands are sorted, and a
// chain that mixes the two keeps its order; either way the chain is written
// back with its methods. Text with no such call keeps its text, with every
// bracketed group inside it canonicalized and the arguments of every call
// sorted: the stand writes a list of values as the arguments of an in or an eq
// call.
func canonicalMethodChain(expr string) string {
	operands, methods := splitMethodChain(expr)
	if len(operands) < 2 {
		return rewriteBracketGroups(expr, func(_, inner string) string {
			parts := splitOutsideBrackets(inner, methodArgumentSeparators[0])
			return joinTerms(parts, methodArgumentSeparators[0], len(parts) > 1, canonicalMethodChain)
		})
	}
	for i := range operands {
		operands[i] = canonicalMethodChain(stripEnclosingBrackets(strings.TrimSpace(operands[i])))
	}
	sameMethod := true
	for _, method := range methods[1:] {
		sameMethod = sameMethod && method == methods[0]
	}
	if sameMethod {
		sort.Strings(operands)
	}
	var out strings.Builder
	out.WriteString(operands[0])
	for i, method := range methods {
		out.WriteString("." + method + "(" + operands[i+1] + ")")
	}
	return out.String()
}

// stripEnclosingBrackets removes one pair of round brackets that encloses the
// whole of expr, and repeats until none does. Brackets inside quotes do not
// count.
func stripEnclosingBrackets(expr string) string {
	for strings.HasPrefix(expr, "(") {
		depth := 0
		var quote byte
		closesAt := -1
		for i := 0; i < len(expr) && closesAt < 0; i++ {
			c := expr[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '(' || c == '[' || c == '{':
				depth++
			case c == ')' || c == ']' || c == '}':
				depth--
				if depth == 0 {
					closesAt = i
				}
			}
		}
		if closesAt != len(expr)-1 {
			return expr
		}
		expr = strings.TrimSpace(expr[1:closesAt])
	}
	return expr
}

// splitMethodChain splits expr at every .and( and .or( outside brackets and
// quotes into the operands of the chain, with the closing bracket of each call
// removed, and returns beside them the method of each call, one fewer than the
// operands. Text with no such call returns no operands.
func splitMethodChain(expr string) (operands, methods []string) {
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && c == '.':
			for _, name := range []string{"and", "or"} {
				call := "." + name + "("
				if !strings.HasPrefix(expr[i:], call) {
					continue
				}
				operand := expr[start:i]
				if len(operands) > 0 {
					operand = strings.TrimSuffix(operand, ")")
				}
				operands = append(operands, operand)
				methods = append(methods, name)
				start = i + len(call)
				i += len(call) - 1
				depth++
				break
			}
		}
	}
	if len(operands) == 0 {
		return nil, nil
	}
	operands = append(operands, strings.TrimSuffix(expr[start:], ")"))
	return operands, methods
}

// splitOutsideBrackets splits expr at every occurrence of sep that is outside
// brackets and quotes. A sep that never occurs there yields one part.
func splitOutsideBrackets(expr, sep string) []string {
	var parts []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && strings.HasPrefix(expr[i:], sep):
			parts = append(parts, expr[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	return append(parts, expr[start:])
}

// rewriteBracketGroups replaces the text inside every outermost bracket group of
// expr, ( ), [ ], or { }, with rewrite of that text, and keeps everything outside
// the groups as it is. Brackets inside quotes do not open a group. Beside the
// text, rewrite gets the prefix of expr up to and including the opening bracket,
// which tells what the group is: the arguments of a call, an IN list, an array.
func rewriteBracketGroups(expr string, rewrite func(prefix, inner string) string) string {
	var out strings.Builder
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[' || c == '{':
			if depth == 0 {
				out.WriteString(expr[start : i+1])
				start = i + 1
			}
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
			if depth == 0 {
				out.WriteString(rewrite(expr[:start], expr[start:i]))
				start = i
			}
		}
	}
	out.WriteString(expr[start:])
	return out.String()
}

// canonicalJSON rewrites a customFilterCondition into compact JSON with every
// array sorted by the JSON text of its elements, at every depth. The golden is
// written with indentation and the stand answers compact, so the two never
// compare equal as bytes; the apply array of a logic node lists its operands in
// the same unstable order as the text dialects, and a params array holds a
// list of values from a PIP answer. A number keeps its digits rather than
// becoming a float64. Text that is not one JSON value, and a null or absent
// value, are returned as they are.
func canonicalJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil || v == nil {
		return raw
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return raw
	}
	compact, err := json.Marshal(sortJSONArrays(v))
	if err != nil {
		return raw
	}
	return compact
}

func sortJSONArrays(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		for key, value := range typed {
			typed[key] = sortJSONArrays(value)
		}
		return typed
	case []any:
		return sortByJSONText(typed, sortJSONArrays)
	default:
		return v
	}
}
