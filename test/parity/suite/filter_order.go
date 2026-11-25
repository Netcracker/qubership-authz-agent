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
	"unicode"

	"authz-agent/test/parity/suite/model"
)

// normalizeFilterOrder applies the order rewrite to every dialect of a filter
// answer, and returns v unchanged for any other golden type.
//
// Access-control joins the predicates of the rules that apply to a filter request
// in an order that differs from one run to the next, at every level of the
// expression: the terms of one OR, the terms of one AND, and the bracketed groups
// of nested sets and of simplified policies. normalizeFilterOrder rewrites each
// filter dialect into a canonical form in which that order does not reach the
// comparison. The form is for comparison only; the golden on disk keeps the text
// the stand answered.
//
// One rule decides which lists are compared without regard to their order, in
// every dialect: a list is unordered where the syntax that holds it gives its
// order no meaning, and keeps its order everywhere else. Two kinds of list are
// unordered:
//
//   - the operands of a logical OR or AND: the OR and AND keywords of SQL, the
//     comma and the semicolon of RSQL, the arrays of $or, $and, and $nor in
//     MongoDB, the or and and calls of a method chain, and the apply array of a
//     node whose op is OR or AND in the logic tree of a customFilterCondition;
//   - a list of values that stands for a set: the list after SQL IN, the operand
//     of RSQL =in= and =out=, the arrays of MongoDB $in and $nin, and the
//     arguments of an in or notIn call.
//
// Every other list keeps its order: the arguments of a function or of any other
// comparison, a literal array, the members of a MongoDB object, every list
// inside the value of a MongoDB $expr at any depth, $in and $or included, since
// an aggregation expression takes its arguments in order, and every other array
// of a customFilterCondition. A dialect tells the kinds apart by the token
// before the opening bracket, matched without regard to case or to the white
// space around it, so SUBSTRING (a, 1) and substring(a, 1) are both a function
// call. The rule does not depend on where a list came from: a list of values the
// stand substitutes from a PIP answer is unordered only where it stands in one
// of the positions above.
//
// The canonical text is not the dialect's own syntax: separators are rejoined
// without the stand's spacing, and a chain of method calls is written back as a
// chain after sorting. Both sides of a comparison pass through the same rewrite,
// so only the difference between them matters.
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
		clone.MongodbFilterCondition = clone.MongodbFilterCondition.Map(infixCanon(mongodbDialect))
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
	r.MongodbFilterCondition = r.MongodbFilterCondition.Map(infixCanon(mongodbDialect))
	r.RsqlFilterCondition = r.RsqlFilterCondition.Map(infixCanon(rsqlDialect))
	r.SqlFilterCondition = r.SqlFilterCondition.Map(infixCanon(sqlDialect))
	r.CustomFilterCondition = canonicalJSON(r.CustomFilterCondition)
}

// A groupKind is what a bracket group of a filter text holds, and decides
// whether the order of its elements reaches the comparison.
type groupKind int

const (
	// groupOrdered holds a list whose order carries meaning, such as the
	// arguments of a function, a literal array, or the members of an object.
	groupOrdered groupKind = iota
	// groupUnordered holds the operands of a logical operator or a list of
	// values that stands for a set.
	groupUnordered
	// groupExpression holds an expression of the dialect's logical operators.
	groupExpression
	// groupVerbatim holds text whose lists all keep their order, at any
	// depth.
	groupVerbatim
)

// An infixDialect is what canonicalInfix needs to know of one infix filter
// dialect.
type infixDialect struct {
	// logical lists the operators that join the operands of a logical OR or
	// AND, from the loosest-binding to the tightest.
	logical []logicalOperator
	// group returns the kind of the bracket group that open opens. before is
	// the text in front of open at the same bracket level, with the white space
	// at its end removed.
	group func(before string, open byte) groupKind
	// quoting is how the dialect writes a quote inside a quoted string.
	quoting quoting
}

// A logicalOperator joins the operands of one logical operation. A keyword
// matches without regard to case where white space, a round bracket, or a
// quote stands on both sides of it (isKeywordBoundary); any other text matches
// as it is.
type logicalOperator struct {
	text    string
	keyword bool
	// closesBetween is set on the SQL AND, whose first occurrence after a
	// BETWEEN keyword ends the range of that BETWEEN and joins no operands.
	closesBetween bool
}

var (
	// rsqlComparison matches the comparison operator at the end of the text
	// before a bracketed RSQL operand, and captures the name of a =name=
	// operator.
	rsqlComparison = regexp.MustCompile(`(?:=([A-Za-z]*)|!)=$`)

	// In SQL, OR binds looser than AND, and the AND of BETWEEN x AND y is part
	// of the range. A bracket right after IN opens a set of values, one right
	// after any other name opens the arguments of a function, and any other
	// bracket groups an expression. A quote inside a string is doubled, and a
	// backslash is a plain character.
	sqlDialect = infixDialect{
		logical: []logicalOperator{{text: "OR", keyword: true}, {text: "AND", keyword: true, closesBetween: true}},
		group: func(before string, open byte) groupKind {
			if open != '(' {
				return groupOrdered
			}
			switch strings.ToUpper(trailingName(before)) {
			case "IN":
				return groupUnordered
			case "", "NOT", "AND", "OR":
				return groupExpression
			}
			return groupOrdered
		},
	}

	// In RSQL, the comma is OR and the semicolon is AND, which binds tighter. A
	// bracket after a comparison operator opens its operand, a set of values
	// for =in= and =out= and an ordered list for any other comparison, such as
	// =between=. A bracket at the start or after a logical operator groups an
	// expression. A backslash escapes the character after it inside a string.
	rsqlDialect = infixDialect{
		quoting: quoting{backslash: true},
		logical: []logicalOperator{{text: ","}, {text: ";"}},
		group: func(before string, open byte) groupKind {
			if open != '(' {
				return groupOrdered
			}
			if before == "" || strings.HasSuffix(before, "(") || strings.HasSuffix(before, ",") || strings.HasSuffix(before, ";") {
				return groupExpression
			}
			if m := rsqlComparison.FindStringSubmatch(before); m != nil {
				switch strings.ToLower(m[1]) {
				case "in", "out":
					return groupUnordered
				}
			}
			return groupOrdered
		},
	}

	// The mongodbFilterCondition text is not always valid JSON, since the stand
	// substitutes values into it as text, so it is read as an infix text with
	// no logical operators of its own: its OR and AND are the arrays of $or and
	// $and. The value of $expr is an aggregation expression, whose arrays are
	// the ordered arguments of its operators, $in included, so nothing in it is
	// reordered. A backslash escapes the character after it inside a string.
	mongodbDialect = infixDialect{
		quoting: quoting{backslash: true},
		group: func(before string, open byte) groupKind {
			if strings.EqualFold(trailingKey(before), "$expr") {
				return groupVerbatim
			}
			if open != '[' {
				return groupOrdered
			}
			switch strings.ToLower(trailingKey(before)) {
			case "$or", "$and", "$nor", "$in", "$nin":
				return groupUnordered
			}
			return groupOrdered
		},
	}
)

// canonicalInfix rewrites an infix filter expression of the dialect d into the
// form in which the lists that [normalizeFilterOrder] calls unordered are sorted.
// The text is split at the first logical operator of d that occurs outside
// brackets and quotes; its operands are canonicalized in turn, trimmed, sorted,
// and joined with that operator. Text that no logical operator splits keeps its
// text outside brackets, and every outermost bracket group in it is rewritten by
// its kind: an expression is canonicalized as a whole, a verbatim group is
// kept as it is, and the comma-separated elements of a list are canonicalized
// and trimmed, then sorted where the list is unordered.
func canonicalInfix(expr string, d infixDialect) string {
	expr = strings.TrimSpace(expr)
	canonicalize := func(part string) string { return canonicalInfix(part, d) }
	for _, op := range d.logical {
		parts := splitLogical(expr, op, d.quoting)
		if len(parts) < 2 {
			continue
		}
		joiner := op.text
		if op.keyword {
			joiner = " " + op.text + " "
		}
		return joinTerms(parts, joiner, true, canonicalize)
	}
	return rewriteBracketGroups(expr, d.quoting, func(prefix, inner string) string {
		open := prefix[len(prefix)-1]
		before := strings.TrimRightFunc(prefix[:len(prefix)-1], unicode.IsSpace)
		switch d.group(before, open) {
		case groupExpression:
			return canonicalize(inner)
		case groupVerbatim:
			return inner
		case groupUnordered:
			return joinTerms(splitOutsideBrackets(inner, ",", d.quoting), ",", true, canonicalize)
		default:
			return joinTerms(splitOutsideBrackets(inner, ",", d.quoting), ",", false, canonicalize)
		}
	})
}

// infixCanon returns canonicalInfix for the dialect d, the form
// [model.FilterText.Map] applies to a dialect's text.
func infixCanon(d infixDialect) func(string) string {
	return func(expr string) string { return canonicalInfix(expr, d) }
}

// trailingName returns the letters, digits, underscores, and dollar signs at
// the end of text, or "" when text ends with any other character.
func trailingName(text string) string {
	i := len(text)
	for i > 0 && isNameByte(text[i-1]) {
		i--
	}
	return text[i:]
}

func isNameByte(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// trailingKey returns the member name that text ends with, as in "$in": or
// $in :, without its quotes, or "" when text does not end with a colon.
func trailingKey(text string) string {
	if !strings.HasSuffix(text, ":") {
		return ""
	}
	text = strings.TrimRightFunc(strings.TrimSuffix(text, ":"), unicode.IsSpace)
	if strings.HasSuffix(text, `"`) {
		opening := strings.LastIndex(text[:len(text)-1], `"`)
		if opening < 0 {
			return ""
		}
		return text[opening+1 : len(text)-1]
	}
	return trailingName(text)
}

// splitLogical splits expr at every occurrence of op outside brackets and
// quotes. An op that never occurs there yields one part. Where op closes a
// BETWEEN, its first occurrence after each BETWEEN keyword does not split.
func splitLogical(expr string, op logicalOperator, q quoting) []string {
	if !op.keyword {
		return splitOutsideBrackets(expr, op.text, q)
	}
	inRange := false
	return splitOutside(expr, q, func(i int) int {
		if op.closesBetween && keywordAt(expr, i, "BETWEEN") {
			inRange = true
			return 0
		}
		if !keywordAt(expr, i, op.text) {
			return 0
		}
		if inRange {
			inRange = false
			return 0
		}
		return len(op.text)
	})
}

// keywordAt reports whether keyword, in any letter case, starts at offset i of
// expr with a keyword boundary on both sides of it.
func keywordAt(expr string, i int, keyword string) bool {
	end := i + len(keyword)
	if i == 0 || end >= len(expr) || !strings.EqualFold(expr[i:end], keyword) {
		return false
	}
	return isKeywordBoundary(expr[i-1]) && isKeywordBoundary(expr[end])
}

// isKeywordBoundary reports whether c can stand next to a keyword: white
// space, a round bracket, or the quote that ends or starts a string.
func isKeywordBoundary(c byte) bool {
	return c == '(' || c == ')' || c == '\'' || c == '"' || unicode.IsSpace(rune(c))
}

// chainQuoting is how a method chain writes a quote inside a quoted string:
// a backslash escapes the character after it.
var chainQuoting = quoting{backslash: true}

// A quoting says how a dialect writes a quote inside a quoted string.
type quoting struct {
	// backslash is set where a backslash escapes the character after it
	// inside a quoted string. Where it is not set, a backslash is a plain
	// character, and a quote inside a string is doubled, which closes the
	// string and opens it again.
	backslash bool
}

// quoteScan follows the quoted strings of a text one byte at a time.
type quoteScan struct {
	quoting
	quote   byte
	escaped bool
}

// quoted reports whether c, the next byte of the text, belongs to a quoted
// string, its quotes included.
func (s *quoteScan) quoted(c byte) bool {
	switch {
	case s.escaped:
		s.escaped = false
		return true
	case s.quote != 0:
		if s.backslash && c == '\\' {
			s.escaped = true
		} else if c == s.quote {
			s.quote = 0
		}
		return true
	case c == '"' || c == '\'':
		s.quote = c
		return true
	}
	return false
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

// canonicalMethodChain rewrites the method chain of filterCondition, such as
// first.and(second).or(third), into the form in which the lists that
// [normalizeFilterOrder] calls unordered are sorted. The chain is split at every and
// and or call outside brackets and quotes, and evaluates from left to right:
// a run of calls of one method joins its operands into one OR or AND, and that
// operation becomes the first operand of the next run. The operands of each run
// are sorted, and the chain is written back with lower-case methods. Each
// operand is stripped of the brackets that enclose it whole, since the stand
// brackets the first operand of a chain and not the others, and is
// canonicalized in turn. Text with no such call keeps its text outside
// brackets, with the arguments of every call canonicalized, and sorted for an
// in or a notIn call.
func canonicalMethodChain(expr string) string {
	operands, methods := splitMethodChain(expr, chainQuoting)
	if len(operands) < 2 {
		return rewriteBracketGroups(expr, chainQuoting, func(prefix, inner string) string {
			parts := splitOutsideBrackets(inner, ",", chainQuoting)
			return joinTerms(parts, ",", callTakesASet(prefix[:len(prefix)-1]), canonicalMethodChain)
		})
	}
	for i := range operands {
		operands[i] = canonicalMethodChain(stripEnclosingBrackets(strings.TrimSpace(operands[i]), chainQuoting))
	}
	run := []string{operands[0]}
	method := methods[0]
	for i, next := range methods {
		if next != method {
			run = []string{writeChain(method, run)}
			method = next
		}
		run = append(run, operands[i+1])
	}
	return writeChain(method, run)
}

// writeChain sorts operands and writes them as one chain of method calls.
func writeChain(method string, operands []string) string {
	sort.Strings(operands)
	var out strings.Builder
	out.WriteString(operands[0])
	for _, operand := range operands[1:] {
		out.WriteString("." + method + "(" + operand + ")")
	}
	return out.String()
}

// callTakesASet reports whether before ends with the name of an in or a notIn
// call, whose arguments are a set of values.
func callTakesASet(before string) bool {
	before = strings.TrimRightFunc(before, unicode.IsSpace)
	name := trailingName(before)
	if !strings.HasSuffix(strings.TrimRightFunc(before[:len(before)-len(name)], unicode.IsSpace), ".") {
		return false
	}
	return strings.EqualFold(name, "in") || strings.EqualFold(name, "notIn")
}

// stripEnclosingBrackets removes one pair of round brackets that encloses the
// whole of expr, and repeats until none does. Brackets inside quotes do not
// count.
func stripEnclosingBrackets(expr string, q quoting) string {
	for strings.HasPrefix(expr, "(") {
		depth := 0
		scan := quoteScan{quoting: q}
		closesAt := -1
		for i := 0; i < len(expr) && closesAt < 0; i++ {
			c := expr[i]
			switch {
			case scan.quoted(c):
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

// splitMethodChain splits expr at every and and or call outside brackets and
// quotes into the operands of the chain, with the closing bracket of each call
// removed, and returns beside them the lower-case method of each call, one
// fewer than the operands. A call matches without regard to case and to white
// space before its bracket. Text with no such call returns no operands.
func splitMethodChain(expr string, q quoting) (operands, methods []string) {
	depth := 0
	scan := quoteScan{quoting: q}
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case scan.quoted(c):
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0 && c == '.':
			name, length := chainCallAt(expr[i+1:])
			if length == 0 {
				continue
			}
			operand := expr[start:i]
			if len(operands) > 0 {
				operand = strings.TrimSuffix(strings.TrimSpace(operand), ")")
			}
			operands = append(operands, operand)
			methods = append(methods, name)
			start = i + 1 + length
			i = start - 1
			depth++
		}
	}
	if len(operands) == 0 {
		return nil, nil
	}
	operands = append(operands, strings.TrimSuffix(strings.TrimSpace(expr[start:]), ")"))
	return operands, methods
}

// chainCallAt reports the lower-case method of an and or an or call that text
// starts with, after any white space, and the length of the call up to and including its opening
// bracket; the length is 0 when text starts with no such call.
func chainCallAt(text string) (method string, length int) {
	call := strings.TrimLeftFunc(text, unicode.IsSpace)
	name := call
	for i := 0; i < len(call); i++ {
		if !isNameByte(call[i]) {
			name = call[:i]
			break
		}
	}
	method = strings.ToLower(name)
	if method != "and" && method != "or" {
		return "", 0
	}
	rest := strings.TrimLeftFunc(call[len(name):], unicode.IsSpace)
	if !strings.HasPrefix(rest, "(") {
		return "", 0
	}
	return method, len(text) - len(rest) + 1
}

// splitOutsideBrackets splits expr at every occurrence of sep that is outside
// brackets and quotes. A sep that never occurs there yields one part.
func splitOutsideBrackets(expr, sep string, q quoting) []string {
	return splitOutside(expr, q, func(i int) int {
		if strings.HasPrefix(expr[i:], sep) {
			return len(sep)
		}
		return 0
	})
}

// splitOutside splits expr at every offset outside brackets and quotes where
// separatorAt returns a length above 0, and drops that many bytes as the
// separator.
func splitOutside(expr string, q quoting, separatorAt func(i int) int) []string {
	var parts []string
	depth := 0
	scan := quoteScan{quoting: q}
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case scan.quoted(c):
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case depth == 0:
			if n := separatorAt(i); n > 0 {
				parts = append(parts, expr[start:i])
				start = i + n
				i = start - 1
			}
		}
	}
	return append(parts, expr[start:])
}

// rewriteBracketGroups replaces the text inside every outermost bracket group of
// expr, ( ), [ ], or { }, with rewrite of that text, and keeps everything outside
// the groups as it is. Brackets inside quotes do not open a group. Beside the
// text, rewrite gets the prefix of expr up to and including the opening bracket,
// which tells what the group is: the arguments of a call, an IN list, an array.
func rewriteBracketGroups(expr string, q quoting, rewrite func(prefix, inner string) string) string {
	var out strings.Builder
	depth := 0
	scan := quoteScan{quoting: q}
	start := 0
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case scan.quoted(c):
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

// canonicalJSON rewrites a customFilterCondition into compact JSON in which the
// apply array of every node whose op is OR or AND in its logic tree, the value
// of its top-level logic member, is sorted by the JSON text of its elements;
// every other array keeps its order, those under data and params included. The
// golden is written with indentation and the stand answers compact, so the two
// never compare equal as bytes, and the members of an object come out in one
// order. A number keeps its digits rather than becoming a float64. Text that is
// not one JSON value, and a null or absent value, are returned as they are.
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
	if condition, ok := v.(map[string]any); ok {
		if logic, ok := condition["logic"]; ok {
			condition["logic"] = canonicalLogicNode(logic)
		}
	}
	compact, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return compact
}

// canonicalLogicNode sorts, in place, the apply array of node when its op is
// OR or AND, in any letter case, does the same for every node of the array
// whatever the op, and returns node. Any other value is returned as it is.
func canonicalLogicNode(node any) any {
	typed, ok := node.(map[string]any)
	if !ok {
		return node
	}
	apply, ok := typed["apply"].([]any)
	if !ok {
		return node
	}
	for i, element := range apply {
		apply[i] = canonicalLogicNode(element)
	}
	if op, _ := typed["op"].(string); strings.EqualFold(op, "OR") || strings.EqualFold(op, "AND") {
		typed["apply"] = sortByJSONText(apply, func(element any) any { return element })
	}
	return typed
}
