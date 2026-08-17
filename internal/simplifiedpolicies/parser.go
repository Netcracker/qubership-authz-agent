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

package simplifiedpolicies

import (
	"fmt"
	"strings"
	"unicode"
)

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenWord
	tokenString
	tokenNumber
	tokenRegex
	tokenLParen
	tokenRParen
	tokenComma
)

type token struct {
	typ   tokenType
	value string
}

type parser struct {
	tokens []token
	pos    int
}

func ParseCondition(input string) (map[string]any, error) {
	tokens, err := tokenize(input)
	if err != nil {
		return nil, err
	}

	p := &parser{tokens: tokens}
	ast, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().typ != tokenEOF {
		return nil, fmt.Errorf("unexpected token %q", p.peek().value)
	}

	normalized, ok := ast.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("condition must not collapse to scalar value")
	}
	return normalized, nil
}

func tokenize(input string) ([]token, error) {
	var tokens []token
	for i := 0; i < len(input); {
		ch := input[i]

		if isWhitespace(ch) {
			i++
			continue
		}

		switch ch {
		case '(':
			tokens = append(tokens, token{typ: tokenLParen, value: "("})
			i++
			continue
		case ')':
			tokens = append(tokens, token{typ: tokenRParen, value: ")"})
			i++
			continue
		case ',':
			tokens = append(tokens, token{typ: tokenComma, value: ","})
			i++
			continue
		case '\'':
			value, next, err := scanQuoted(input, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{typ: tokenString, value: value})
			i = next
			continue
		case '/':
			value, next := scanUntilDelimiter(input, i)
			tokens = append(tokens, token{typ: tokenRegex, value: value})
			i = next
			continue
		}

		if isNumericStart(input, i) {
			value, next := scanNumber(input, i)
			tokens = append(tokens, token{typ: tokenNumber, value: value})
			i = next
			continue
		}

		value, next := scanWord(input, i)
		tokens = append(tokens, token{typ: tokenWord, value: value})
		i = next
	}

	tokens = append(tokens, token{typ: tokenEOF})
	return tokens, nil
}

func (p *parser) parseOr() (any, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}

	args := []any{left}
	for p.matchWord("OR") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		args = append(args, right)
	}

	if len(args) == 1 {
		return left, nil
	}
	return map[string]any{"op": "or", "args": args}, nil
}

func (p *parser) parseAnd() (any, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	args := []any{left}
	for p.matchWord("AND") {
		right, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		args = append(args, right)
	}

	if len(args) == 1 {
		return left, nil
	}
	return map[string]any{"op": "and", "args": args}, nil
}

func (p *parser) parsePrimary() (any, error) {
	if p.peek().typ == tokenLParen {
		p.next()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().typ != tokenRParen {
			return nil, fmt.Errorf("expected ')'")
		}
		p.next()
		return expr, nil
	}

	if p.lookaheadHasAccess() {
		return p.parseHasAccess()
	}

	if p.peek().typ == tokenWord {
		switch strings.ToLower(p.peek().value) {
		case "true":
			p.next()
			return map[string]any{"const": true}, nil
		case "false":
			p.next()
			return map[string]any{"const": false}, nil
		}
	}

	return p.parseComparison()
}

func (p *parser) parseComparison() (any, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}

	switch {
	case p.matchWords("NOT", "CONTAINS", "ANY"):
		right, err := p.parseMultiRightOperand("contains_any")
		if err != nil {
			return nil, err
		}
		return negate("contains_any", left, right), nil
	case p.matchWords("NOT", "CONTAINS"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return negate("contains", left, right), nil
	case p.matchWords("NOT", "EQUALS"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("neq", left, right), nil
	case p.matchWords("NOT", "IN"):
		right, err := p.parseMultiRightOperand("in")
		if err != nil {
			return nil, err
		}
		return negate("in", left, right), nil
	case p.matchWords("NOT", "MATCH"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return negate("match", left, right), nil
	case p.matchWords("IS", "NOT", "EMPTY"):
		return negate("is_empty", left), nil
	case p.matchWords("IS", "NOT", "NULL"):
		return negate("is_null", left), nil
	case p.matchWords("IS", "NOT", "SUBSET"):
		right, err := p.parseMultiRightOperand("is_subset")
		if err != nil {
			return nil, err
		}
		return negate("is_subset", left, right), nil
	case p.matchWords("CONTAINS", "ANY"):
		right, err := p.parseMultiRightOperand("contains_any")
		if err != nil {
			return nil, err
		}
		return node("contains_any", left, right), nil
	case p.matchWords("CONTAINS"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("contains", left, right), nil
	case p.matchWords("EQUALS"), p.matchSymbol("=="), p.matchSymbol("="):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("eq", left, right), nil
	case p.matchSymbol("!="):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("neq", left, right), nil
	case p.matchWords("IN"):
		right, err := p.parseMultiRightOperand("in")
		if err != nil {
			return nil, err
		}
		return node("in", left, right), nil
	case p.matchWords("MATCH"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("match", left, right), nil
	case p.matchWords("IS", "EMPTY"):
		return node("is_empty", left), nil
	case p.matchWords("IS", "NULL"):
		return node("is_null", left), nil
	case p.matchWords("IS", "SUBSET"):
		right, err := p.parseMultiRightOperand("is_subset")
		if err != nil {
			return nil, err
		}
		return node("is_subset", left, right), nil
	case p.matchWords("GREATER", "THAN", "OR", "EQUALS", "TO"), p.matchWords("GREATER", "THAN", "OR", "EQUAL", "TO"), p.matchSymbol(">="):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("gte", left, right), nil
	case p.matchWords("GREATER", "THAN"), p.matchSymbol(">"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("gt", left, right), nil
	case p.matchWords("LESS", "THAN", "OR", "EQUALS", "TO"), p.matchWords("LESS", "THAN", "OR", "EQUAL", "TO"), p.matchSymbol("<="):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("lte", left, right), nil
	case p.matchWords("LESS", "THAN"), p.matchSymbol("<"):
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return node("lt", left, right), nil
	default:
		return nil, fmt.Errorf("unsupported operator near %q", p.peek().value)
	}
}

func (p *parser) parseHasAccess() (map[string]any, error) {
	subject := p.next()
	if !strings.EqualFold(subject.value, "subject") {
		return nil, fmt.Errorf("expected subject")
	}

	modeToken := p.next()
	mode := strings.ToLower(modeToken.value)
	if mode != "allowed" && mode != "denied" {
		return nil, fmt.Errorf("expected allowed or denied")
	}

	operation := p.next()
	if operation.typ != tokenString && operation.typ != tokenWord {
		return nil, fmt.Errorf("expected operation literal")
	}

	if !p.matchWord("ON") {
		return nil, fmt.Errorf("expected ON")
	}

	resource := p.next()
	if !strings.EqualFold(resource.value, "resource") {
		return nil, fmt.Errorf("expected resource")
	}

	return map[string]any{
		"op": "has_access",
		"args": []any{
			map[string]any{"const": mode},
			map[string]any{"const": operation.value},
			map[string]any{"const": "resource"},
			map[string]any{"const": 1},
		},
	}, nil
}

func (p *parser) parseOperand() (map[string]any, error) {
	current := p.next()
	switch current.typ {
	case tokenString:
		return map[string]any{"const": current.value}, nil
	case tokenRegex:
		return map[string]any{"const": current.value}, nil
	case tokenNumber:
		if value, ok := toNumber(current.value); ok {
			return map[string]any{"const": value}, nil
		}
		return nil, fmt.Errorf("invalid number %q", current.value)
	case tokenWord:
		lower := strings.ToLower(current.value)
		switch lower {
		case "true":
			return map[string]any{"const": true}, nil
		case "false":
			return map[string]any{"const": false}, nil
		}
		// D-AG-11 / ADR-0054: the composite entitlements operand
		// `subject.entitledResources.of('<rt>').as('<n1>', ...)(.as(...))*`
		// reaches parseOperand as a single tokenWord — `scanWord` swallows
		// the `.of(...)`/`.as(...)` method-call groups as part of the word.
		// It must be detected before the `subject.` catchall so the ref AST
		// carries the structured scope instead of collapsing into splitPath.
		if ent, err := parseEntitlementOperand(current.value); err != nil {
			return nil, err
		} else if ent != nil {
			return ent, nil
		}
		if strings.HasPrefix(lower, "resource.") {
			path := current.value[len("resource."):]
			return ref("resource", splitPath(path)), nil
		}
		if strings.HasPrefix(lower, "subject.") {
			path := current.value[len("subject."):]
			return ref("subject", splitPath(path)), nil
		}
		return map[string]any{"const": current.value}, nil
	default:
		return nil, fmt.Errorf("unexpected token %q", current.value)
	}
}

// parseEntitlementOperand recognises the composite entitlements operand
// defined by ADR-0054 + D-AG-11 and emits the AST node shape consumed by
// rls.rego's entitlement ref scope:
//
//	{
//	  "ref": {
//	    "scope":        "entitlements",
//	    "resourceType": "<literal>",
//	    "names":        ["<name1>", "<name2>", ...]
//	  }
//	}
//
// Chained `.as(...).as(...)` and multi-name `.as('A', 'B')` are both
// collapsed into the same flat `names` list per D-AG-12 (UNION semantics
// at evaluation time).
//
// Returns `nil, nil` when the input does not start with the entitlements
// prefix so parseOperand can fall through to the generic subject-ref path.
// Returns a non-nil error when the prefix matches but the remaining
// method-call chain is malformed — that surfaces as a policy upload 400
// instead of silently degrading to a literal-constant token.
func parseEntitlementOperand(raw string) (map[string]any, error) {
	const prefix = "subject.entitledResources.of("
	lowerPrefix := strings.ToLower(prefix)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, lowerPrefix) {
		return nil, nil
	}
	rest := raw[len(prefix):]

	resourceType, next, err := readSingleQuotedLiteral(rest)
	if err != nil {
		return nil, fmt.Errorf("entitlements operand: %w", err)
	}
	rest = strings.TrimLeft(next, " \t\r\n")
	if !strings.HasPrefix(rest, ")") {
		return nil, fmt.Errorf("entitlements operand: expected ')' after resource type, got %q", rest)
	}
	rest = rest[1:]

	var names []string
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			break
		}
		if !strings.HasPrefix(strings.ToLower(rest), ".as(") {
			return nil, fmt.Errorf("entitlements operand: expected .as(...) clause, got %q", rest)
		}
		rest = rest[len(".as("):]
		for {
			rest = strings.TrimLeft(rest, " \t\r\n")
			name, afterName, err := readSingleQuotedLiteral(rest)
			if err != nil {
				return nil, fmt.Errorf("entitlements operand: %w", err)
			}
			names = append(names, name)
			rest = strings.TrimLeft(afterName, " \t\r\n")
			if strings.HasPrefix(rest, ",") {
				rest = rest[1:]
				continue
			}
			break
		}
		if !strings.HasPrefix(rest, ")") {
			return nil, fmt.Errorf("entitlements operand: expected ')' after .as(...) names, got %q", rest)
		}
		rest = rest[1:]
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("entitlements operand: at least one .as('<name>') clause is required")
	}

	namesAny := make([]any, 0, len(names))
	for _, n := range names {
		namesAny = append(namesAny, n)
	}

	return map[string]any{
		"ref": map[string]any{
			"scope":        "entitlements",
			"resourceType": resourceType,
			"names":        namesAny,
		},
	}, nil
}

func readSingleQuotedLiteral(input string) (string, string, error) {
	if len(input) == 0 || input[0] != '\'' {
		return "", "", fmt.Errorf("expected single-quoted string literal, got %q", input)
	}
	var builder strings.Builder
	for i := 1; i < len(input); i++ {
		ch := input[i]
		if ch == '\\' && i+1 < len(input) {
			i++
			builder.WriteByte(input[i])
			continue
		}
		if ch == '\'' {
			return builder.String(), input[i+1:], nil
		}
		builder.WriteByte(ch)
	}
	return "", "", fmt.Errorf("unterminated single-quoted string in %q", input)
}

func (p *parser) parseMultiRightOperand(op string) (map[string]any, error) {
	first, err := p.parseOperand()
	if err != nil {
		return nil, err
	}

	if p.peek().typ != tokenComma {
		if op == "contains_any" || op == "is_subset" || op == "in" {
			if _, ok := first["const"]; ok {
				return map[string]any{"const": []any{first["const"]}}, nil
			}
		}
		return first, nil
	}

	values := []any{}
	if constValue, ok := first["const"]; ok {
		values = append(values, constValue)
	} else {
		return nil, fmt.Errorf("multi-value right operand must be literal list")
	}

	for p.peek().typ == tokenComma {
		p.next()
		item, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		constValue, ok := item["const"]
		if !ok {
			return nil, fmt.Errorf("multi-value right operand must be literal list")
		}
		values = append(values, constValue)
	}

	return map[string]any{"const": values}, nil
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{typ: tokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	current := p.peek()
	if p.pos < len(p.tokens) {
		p.pos++
	}
	return current
}

func (p *parser) matchWord(expected string) bool {
	current := p.peek()
	if current.typ != tokenWord {
		return false
	}
	if !strings.EqualFold(current.value, expected) {
		return false
	}
	p.next()
	return true
}

func (p *parser) matchWords(expected ...string) bool {
	start := p.pos
	for _, item := range expected {
		if !p.matchWord(item) {
			p.pos = start
			return false
		}
	}
	return true
}

func (p *parser) matchSymbol(symbol string) bool {
	current := p.peek()
	if current.typ != tokenWord {
		return false
	}
	if current.value != symbol {
		return false
	}
	p.next()
	return true
}

func (p *parser) lookaheadHasAccess() bool {
	if p.peek().typ != tokenWord || !strings.EqualFold(p.peek().value, "subject") {
		return false
	}
	if p.pos+3 >= len(p.tokens) {
		return false
	}
	mode := p.tokens[p.pos+1]
	on := p.tokens[p.pos+3]
	return mode.typ == tokenWord &&
		(strings.EqualFold(mode.value, "allowed") || strings.EqualFold(mode.value, "denied")) &&
		on.typ == tokenWord &&
		strings.EqualFold(on.value, "on")
}

func node(op string, args ...map[string]any) map[string]any {
	out := make([]any, 0, len(args))
	for _, arg := range args {
		out = append(out, arg)
	}
	return map[string]any{
		"op":   op,
		"args": out,
	}
}

func negate(op string, args ...map[string]any) map[string]any {
	return map[string]any{
		"op": "not",
		"args": []any{
			node(op, args...),
		},
	}
}

func ref(scope string, path []string) map[string]any {
	return map[string]any{
		"ref": map[string]any{
			"scope": scope,
			"path":  path,
		},
	}
}

func splitPath(path string) []string {
	if path == "" {
		return []string{""}
	}
	if strings.ContainsAny(path, "[]?-") {
		return []string{path}
	}
	parts := strings.Split(path, ".")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return []string{path}
	}
	return out
}

func scanQuoted(input string, start int) (string, int, error) {
	var builder strings.Builder
	for i := start + 1; i < len(input); i++ {
		ch := input[i]
		if ch == '\\' && i+1 < len(input) {
			i++
			builder.WriteByte(input[i])
			continue
		}
		if ch == '\'' {
			return builder.String(), i + 1, nil
		}
		builder.WriteByte(ch)
	}
	return "", 0, fmt.Errorf("unterminated quoted string")
}

func scanUntilDelimiter(input string, start int) (string, int) {
	i := start
	for i < len(input) {
		ch := input[i]
		if isWhitespace(ch) || ch == ')' || ch == ',' {
			break
		}
		i++
	}
	return input[start:i], i
}

func scanNumber(input string, start int) (string, int) {
	i := start
	if input[i] == '-' {
		i++
	}
	for i < len(input) && (unicode.IsDigit(rune(input[i])) || input[i] == '.') {
		i++
	}
	return input[start:i], i
}

func scanWord(input string, start int) (string, int) {
	i := start
	bracketDepth := 0
	parenDepth := 0
	quote := byte(0)
	for i < len(input) {
		ch := input[i]
		if quote != 0 {
			if ch == '\\' && i+1 < len(input) {
				i += 2
				continue
			}
			if ch == quote {
				quote = 0
			}
			i++
			continue
		}

		switch ch {
		case '\'', '"':
			quote = ch
			i++
			continue
		case '[':
			bracketDepth++
			i++
			continue
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
			i++
			continue
		case '(':
			// D-AG-11 / ADR-0054: the entitlements composite operand is
			// `subject.entitledResources.of('<rt>').as('<name>', ...).as(...)*`
			// — a single token whose internal `(...)` groups must not
			// terminate the word. Only swallow the group when the word
			// accumulated so far is recognisably an entitlements method
			// chain; every other `(` at `bracketDepth == 0` terminates
			// the word exactly as before so `parsePrimary` can treat the
			// `(` as a sub-expression opener.
			if bracketDepth == 0 && parenDepth == 0 {
				if !isEntitlementMethodCallContinuation(input[start:i]) {
					return input[start:i], i
				}
				parenDepth++
				i++
				continue
			}
			parenDepth++
			i++
			continue
		case ')':
			if parenDepth > 0 {
				parenDepth--
				i++
				continue
			}
			if bracketDepth == 0 {
				return input[start:i], i
			}
		case ',':
			if bracketDepth == 0 && parenDepth == 0 {
				return input[start:i], i
			}
		}

		if bracketDepth == 0 && parenDepth == 0 && isWhitespace(ch) {
			return input[start:i], i
		}

		i++
	}
	return input[start:i], i
}

// isEntitlementMethodCallContinuation reports whether the accumulated word
// fragment is the prefix of an entitlements composite operand at a
// point where the next `(` opens either the `.of(...)` literal group or a
// `.as(...)` name list. Scoped tightly to the `subject.entitledResources`
// path so every other DSL shape keeps the pre-ADR-0054 tokenization.
func isEntitlementMethodCallContinuation(word string) bool {
	lower := strings.ToLower(word)
	if !strings.HasPrefix(lower, "subject.entitledresources") {
		return false
	}
	return strings.HasSuffix(lower, ".of") || strings.HasSuffix(lower, ".as")
}

func isNumericStart(input string, idx int) bool {
	ch := input[idx]
	if ch == '-' {
		return idx+1 < len(input) && unicode.IsDigit(rune(input[idx+1]))
	}
	return unicode.IsDigit(rune(ch))
}

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t'
}
