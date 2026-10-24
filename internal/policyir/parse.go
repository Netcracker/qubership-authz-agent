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

package policyir

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"authz-agent/internal/jsonpath"
)

// SyntaxError reports condition text the PAP refuses to store.
type SyntaxError struct {
	Text   string
	Reason string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("condition %q: %s", e.Text, e.Reason)
}

// ParseCondition parses the text of a target or a condition at place. Text
// "true" or "false" in any letter case, and empty text, are constants. iterVar
// is the [Iterate.Var] of the innermost enclosing iterate, or empty: inside one,
// subject.permissionScope reads the pass as a [PassValue].
//
// A resource path the agent cannot execute yet becomes an [Unsupported]
// operand, except on the right of MATCH and NOT MATCH, where the path is
// pattern text. Text the PAP refuses returns a *SyntaxError.
func ParseCondition(text string, place Place, iterVar string) (*Condition, error) {
	if strings.EqualFold(text, "true") || strings.EqualFold(text, "false") {
		return NewCondition(place, []Atom{Const{Value: strings.EqualFold(text, "true")}})
	}
	p, err := newParser(text)
	if err != nil {
		return nil, err
	}
	p.iterVar = iterVar
	disjuncts, err := p.expr()
	if err != nil {
		return nil, err
	}
	c, err := NewCondition(place, disjuncts...)
	if err != nil {
		return nil, p.fail(err.Error())
	}
	return c, nil
}

type parser struct {
	text    string
	s       string
	i       int
	iterVar string
}

var (
	quotedRE        = regexp.MustCompile(`'[^']*'`)
	listCommaRE     = regexp.MustCompile(`(''|\p{Nd}) *, *`)
	bracketsRE      = regexp.MustCompile(`\[[^\]]*\]`)
	bracketParenRE  = regexp.MustCompile(`\[[^\]]*\]|\([^()]*\)`)
	tightCompareRE  = regexp.MustCompile(`[^ !=<>](==|!=|<=|>=)|(==|!=|<=|>=)[^ ]`)
	connectiveRE    = regexp.MustCompile(`(OR|AND) `)
	lowerKeywordRE  = regexp.MustCompile(`^(or|and)\b`)
	lowerOpRE       = regexp.MustCompile(`^(is|and|or|in|contains|match)\b`)
	misspelledOpRE  = regexp.MustCompile(`^(LESS|GREATER) THAN OR EQUALS? ?`)
	stringLitRE     = regexp.MustCompile(`^'([^']*)'`)
	numberLitRE     = regexp.MustCompile(`^(?:\p{Nd}+(?:\.\p{Nd}+)?|-[1-9]\p{Nd}*(?:\.\p{Nd}+)?|-0\.\p{Nd}*[1-9])`)
	numberStartRE   = regexp.MustCompile(`^-?[\p{Nd}.]`)
	entitledRE      = regexp.MustCompile(`^subject\.entitledResources\.of\('([^']*)'\)\.as\(('[^']*'(?: *, *'[^']*')*)\)`)
	entitledAsRE    = regexp.MustCompile(`'([^']*)'`)
	subjectStepRE   = regexp.MustCompile(`^subject\.(id|name|type|serviceAccount)\.`)
	bracketIndexRE  = regexp.MustCompile(`\[ *(-?\p{Nd}+) *\]`)
	accessRE        = regexp.MustCompile(`^subject (allowed|denied) '([^']*)' on resource`)
	constAtomRE     = regexp.MustCompile(`^(TRUE|FALSE|true|false)`)
	patternTokenRE  = regexp.MustCompile(`^\S+`)
	patternNumberRE = regexp.MustCompile(`^-?\p{Nd}+(?:\.\p{Nd}+)?$`)
	filteredRE      = regexp.MustCompile(`^ FILTERED '([^']*)'`)
	listMoreRE      = regexp.MustCompile(`^ *,`)

	pathKey     = `[A-Za-z0-9_@][A-Za-z0-9_/:$~@!&|-]*`
	jpFunction  = `\.(?:length|min|max|avg|sum|first|last|keys)\(\)`
	jpFilter    = `\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\]|\[\?\((?:[^\[\]()]|\([^()]*\)|\[[^\[\]?]*\])*\)\])*\)\]`
	pathStepsRE = regexp.MustCompile(`^(?:resource|subject)(?:` + jpFunction + `|\.\.?` + pathKey + `|` + jpFilter + `|\[[^\]]*\])+\.?`)
	bareNameRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_*-]*(?:(?:\.\.?` + pathKey + `)|\[[^\]]*\])*`)
)

var keywords = map[string]bool{
	"OR": true, "AND": true, "IS": true, "NOT": true, "NULL": true, "IN": true, "CONTAINS": true, "ANY": true,
	"SUBSET": true, "EMPTY": true, "MATCH": true, "TRUE": true, "FALSE": true, "GREATER": true, "LESS": true,
	"THAN": true, "EQUAL": true, "EQUALS": true, "on": true,
}

// opWords lists the operator spellings, longer phrases before their prefixes.
var opWords = []struct {
	word string
	op   Operator
}{
	{"GREATER THAN OR EQUAL TO", OpGE}, {"LESS THAN OR EQUAL TO", OpLE},
	{"GREATER THAN", OpGT}, {"LESS THAN", OpLT},
	{"IS NOT NULL", OpIsNotNull}, {"IS NULL", OpIsNull}, {"IS NOT EMPTY", OpIsNotEmpty}, {"IS EMPTY", OpIsEmpty},
	{"IS NOT SUBSET", OpIsNotSubset}, {"IS SUBSET", OpIsSubset},
	{"NOT CONTAINS ANY", OpNotContainsAny}, {"CONTAINS ANY", OpContainsAny},
	{"NOT CONTAINS", OpNotContains}, {"CONTAINS", OpContains},
	{"NOT IN", OpNotIn}, {"IN", OpIn}, {"NOT MATCH", OpNotMatch}, {"MATCH", OpMatch},
	{"NOT EQUALS", OpNE}, {"EQUALS", OpEQ}, {"==", OpEQ}, {"!=", OpNE}, {"<=", OpLE}, {">=", OpGE},
	{"<", OpLT}, {">", OpGT}, {"=", OpEQ},
}

func newParser(text string) (*parser, error) {
	fail := func(reason string) (*parser, error) { return nil, &SyntaxError{Text: text, Reason: reason} }
	if text != "" && strings.TrimSpace(text) == "" {
		return fail("blank")
	}
	s, ok := dropLineBreaks(text)
	if !ok {
		return fail("tab or line break between tokens")
	}
	s = strings.Trim(s, " ")
	masked := quotedRE.ReplaceAllString(s, "''")
	masked = joinListCommas(masked)
	outside := bracketsRE.ReplaceAllString(masked, "[]")
	for i := 0; i+1 < len(outside); i++ {
		if outside[i] == ' ' && outside[i+1] == ' ' && (i == 0 || outside[i-1] != ',') {
			return fail("double space")
		}
	}
	bare := bracketParenRE.ReplaceAllString(masked, "_")
	if tightCompareRE.MatchString(bare) {
		return fail("no space around a comparison")
	}
	for _, loc := range connectiveRE.FindAllStringIndex(bare, -1) {
		if loc[0] == 0 || !isSpaceOrWord(lastRune(bare[:loc[0]])) {
			return fail("no space before a connective")
		}
	}
	return &parser{text: text, s: s}, nil
}

// dropLineBreaks drops a tab, a line feed, or a carriage return outside a
// string where it stands beside a space or at either end, and reports false
// where one stands for the single space between two tokens.
func dropLineBreaks(s string) (string, bool) {
	var out strings.Builder
	quoted := false
	for i, ch := range s {
		if ch == '\'' {
			quoted = !quoted
		}
		if (ch == '\t' || ch == '\n' || ch == '\r') && !quoted {
			prev := lastRune(out.String())
			next := s[i+1:]
			if out.Len() == 0 || prev == ' ' || strings.HasPrefix(next, " ") || strings.TrimSpace(s[i:]) == "" {
				continue
			}
			return "", false
		}
		out.WriteRune(ch)
	}
	return out.String(), true
}

// joinListCommas removes the spaces around each comma between two list
// elements, so a list counts as one token for the spacing checks.
func joinListCommas(masked string) string {
	var out strings.Builder
	rest := masked
	for {
		loc := listCommaRE.FindStringSubmatchIndex(rest)
		if loc == nil {
			out.WriteString(rest)
			return out.String()
		}
		after := rest[loc[1]:]
		if strings.HasPrefix(after, "''") || startsWithNumber(after) {
			out.WriteString(rest[:loc[0]])
			out.WriteString(rest[loc[2]:loc[3]])
			out.WriteByte(',')
		} else {
			out.WriteString(rest[:loc[2]+1])
			loc[1] = loc[2] + 1
		}
		rest = rest[loc[1]:]
	}
}

func startsWithNumber(s string) bool {
	return unicode.IsDigit(firstRune(strings.TrimPrefix(s, "-")))
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func firstRune(s string) rune {
	r, _ := utf8.DecodeRuneInString(s)
	return r
}

func isWord(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isSpaceOrWord(r rune) bool {
	return r == ' ' || isWord(r)
}

// endsToken reports whether rest, the text after a literal, starts with
// neither a word character nor a dot.
func endsToken(rest string) bool {
	if rest == "" {
		return true
	}
	r := firstRune(rest)
	return !isWord(r) && r != '.'
}

func (p *parser) fail(reason string) error {
	return &SyntaxError{Text: p.text, Reason: reason}
}

func (p *parser) rest() string { return p.s[p.i:] }

func (p *parser) ws() {
	if p.i < len(p.s) && p.s[p.i] == ' ' {
		p.i++
	}
}

// at reports whether w starts at the current position and is not the prefix
// of a longer word.
func (p *parser) at(w string) bool {
	if !strings.HasPrefix(p.rest(), w) {
		return false
	}
	j := p.i + len(w)
	if j == len(p.s) {
		return true
	}
	return !isWord(firstRune(p.s[j:])) || !unicode.IsLetter(lastRune(w))
}

func (p *parser) eat(w string) bool {
	save := p.i
	p.ws()
	if p.at(w) {
		p.i += len(w)
		return true
	}
	p.i = save
	return false
}

func (p *parser) expr() ([][]Atom, error) {
	if p.s == "" {
		return [][]Atom{{Const{Value: true}}}, nil
	}
	var ors [][]Atom
	for {
		c, err := p.conj()
		if err != nil {
			return nil, err
		}
		ors = append(ors, c)
		if !p.eat("OR") {
			break
		}
	}
	p.ws()
	if p.i != len(p.s) {
		if lowerKeywordRE.MatchString(p.rest()) {
			return nil, p.fail("lower-case keyword")
		}
		return nil, p.fail("trailing text: " + truncate(p.rest(), 30))
	}
	return ors, nil
}

func (p *parser) conj() ([]Atom, error) {
	var ands []Atom
	for {
		a, err := p.atom()
		if err != nil {
			return nil, err
		}
		ands = append(ands, a)
		if !p.eat("AND") {
			return ands, nil
		}
	}
}

// followedByConnective reports whether rest is empty or starts with " OR " or
// " AND ".
func followedByConnective(rest string) bool {
	return rest == "" || strings.HasPrefix(rest, " OR ") || strings.HasPrefix(rest, " AND ")
}

func (p *parser) atom() (Atom, error) {
	p.ws()
	rest := p.rest()
	if m := accessRE.FindStringSubmatch(rest); m != nil && endsToken(rest[len(m[0]):]) {
		p.i += len(m[0])
		return Access{Denied: m[1] == "denied", Operation: m[2]}, nil
	}
	if strings.HasPrefix(rest, "subject.isM2M") && followedByConnective(rest[len("subject.isM2M"):]) {
		p.i += len("subject.isM2M")
		return IsM2M{}, nil
	}
	if m := constAtomRE.FindString(rest); m != "" && followedByConnective(rest[len(m):]) {
		p.i += len(m)
		return Const{Value: strings.EqualFold(m, "TRUE")}, nil
	}
	left, err := p.operand()
	if err != nil {
		return nil, err
	}
	p.ws()
	var op Operator
	for _, w := range opWords {
		if p.at(w.word) {
			op = w.op
			p.i += len(w.word)
			break
		}
	}
	if op == "" {
		switch {
		case lowerOpRE.MatchString(p.rest()):
			return nil, p.fail("lower-case keyword")
		case misspelledOpRE.MatchString(p.rest()):
			return nil, p.fail("misspelled word operator")
		default:
			return nil, p.fail("operator at: " + truncate(p.rest(), 25))
		}
	}
	if op.Unary() {
		return p.compare(op, left, nil)
	}
	p.ws()
	if op == OpMatch || op == OpNotMatch {
		right, err := p.pattern()
		if err != nil {
			return nil, err
		}
		return p.compare(op, left, right)
	}
	start := p.i
	right, err := p.operand()
	if err != nil {
		return nil, err
	}
	if m := filteredRE.FindStringSubmatch(p.rest()); m != nil {
		if ref, ok := right.(PIPRef); ok {
			p.i += len(m[0])
			right = PIPRef{Name: ref.Name + ".filtered", Filtered: true, FilteredOperation: m[1]}
		}
	}
	if op.TakesList() {
		if lit, ok := right.(Literal); ok {
			right, err = p.list(lit, start)
			if err != nil {
				return nil, err
			}
		}
	}
	return p.compare(op, left, right)
}

// compare returns the comparison, with an operand its position does not admit
// reported as a *SyntaxError.
func (p *parser) compare(op Operator, left, right Operand) (Atom, error) {
	c, err := NewCompare(op, left, right)
	if err != nil {
		return nil, p.fail(err.Error())
	}
	return c, nil
}

func (p *parser) pattern() (Operand, error) {
	tok := patternTokenRE.FindString(p.rest())
	if tok == "" {
		return nil, p.fail("MATCH without a pattern")
	}
	p.i += len(tok)
	switch {
	case strings.HasPrefix(tok, "'") || strings.HasPrefix(tok, `"`):
		return nil, p.fail("quoted MATCH pattern")
	case strings.Contains(tok, "{"):
		return nil, p.fail("placeholder in MATCH pattern")
	case patternNumberRE.MatchString(tok):
		return nil, p.fail("number as a MATCH pattern")
	case !isASCII(tok) || strings.Contains(tok, "+") || tok == "resource" || tok == "subject":
		return nil, p.fail("MATCH pattern: " + tok)
	// The pattern is the text of the attribute operand, which is never read,
	// so the path need not compile.
	case strings.HasPrefix(tok, "subject.") && strings.Contains(tok, "["):
		return Resource{Path: "." + tok}, nil
	case strings.HasPrefix(tok, "resource."):
		return Resource{Path: tok[len("resource"):]}, nil
	case strings.HasPrefix(tok, "subject."):
		return p.subject(tok[len("subject."):]), nil
	}
	return Pattern{Text: tok}, nil
}

// list reads the rest of a list whose first literal, first, has just been
// read from position start.
func (p *parser) list(first Literal, start int) (List, error) {
	items := []Literal{first}
	for listMoreRE.MatchString(p.rest()) {
		p.i = strings.Index(p.s[p.i:], ",") + p.i + 1
		for strings.HasPrefix(p.rest(), " ") {
			p.i++
		}
		lit, err := p.literal()
		if err != nil {
			return List{}, err
		}
		l, ok := lit.(Literal)
		if !ok {
			return List{}, p.fail("list element")
		}
		items = append(items, l)
	}
	raw := ""
	if len(items) > 1 {
		raw = p.s[start:p.i]
	}
	l := List{Items: items, Raw: raw}
	if err := validateList(l); err != nil {
		return List{}, p.fail("mixed-type list")
	}
	return l, nil
}

// literal reads a literal at the current position, and returns nil with no
// error when there is none.
func (p *parser) literal() (Operand, error) {
	rest := p.rest()
	if m := stringLitRE.FindStringSubmatch(rest); m != nil {
		p.i += len(m[0])
		return String{Value: m[1]}, nil
	}
	if strings.HasPrefix(rest, `"`) {
		return nil, p.fail("double-quoted string")
	}
	if m := numberLitRE.FindString(rest); m != "" && endsToken(rest[len(m):]) {
		p.i += len(m)
		return Number{Text: m}, nil
	}
	if numberStartRE.MatchString(rest) {
		return nil, p.fail("number: " + truncate(rest, 10))
	}
	for _, w := range []string{"TRUE", "true", "FALSE", "false"} {
		if strings.HasPrefix(rest, w) && endsToken(rest[len(w):]) {
			p.i += len(w)
			return Bool{Value: strings.EqualFold(w, "true")}, nil
		}
	}
	if strings.HasPrefix(rest, "null") && endsToken(rest[len("null"):]) {
		p.i += len("null")
		return Null{}, nil
	}
	return nil, nil
}

func (p *parser) operand() (Operand, error) {
	p.ws()
	lit, err := p.literal()
	if err != nil || lit != nil {
		return lit, err
	}
	rest := p.rest()
	if m := entitledRE.FindStringSubmatch(rest); m != nil {
		p.i += len(m[0])
		var as []string
		for _, a := range entitledAsRE.FindAllStringSubmatch(m[2], -1) {
			as = append(as, a[1])
		}
		return Entitled{ResourceType: m[1], As: as}, nil
	}
	if strings.HasPrefix(rest, "NOT ") {
		return nil, p.fail("standalone NOT")
	}
	path := pathStepsRE.FindString(rest)
	if path == "" && strings.HasPrefix(rest, "resource") && !continuesPath(rest[len("resource"):]) {
		path = "resource"
	}
	if path == "" {
		path = bareNameRE.FindString(rest)
	}
	if path == "" || keywords[path] {
		return nil, p.fail("operand: " + truncate(rest, 30))
	}
	if strings.Contains(path, "[]") || strings.Contains(path, `"`) {
		return nil, p.fail("operand: empty brackets or double quotes in a path")
	}
	if path == "subject.entitledResources" || subjectStepRE.MatchString(path) {
		return nil, p.fail("operand: a step after a subject attribute")
	}
	p.i += len(path)
	written := path
	if strings.HasSuffix(path, ".") && !strings.HasSuffix(path, "..") {
		path = strings.TrimRight(path, ".")
	}
	path = bracketIndexRE.ReplaceAllString(path, "[$1]")
	switch {
	case path == "operation":
		return Operation{}, nil
	case path == "resourceType":
		return ResourceType{}, nil
	case path == "resource" || strings.HasPrefix(path, "resource.") || strings.HasPrefix(path, "resource["):
		return p.resource(path[len("resource"):], written), nil
	case strings.HasPrefix(path, "subject.") && strings.Contains(path, "["):
		return p.resource("."+path, written), nil
	case strings.HasPrefix(path, "subject."):
		return p.subject(path[len("subject."):]), nil
	case path == "subject":
		return nil, p.fail("bare subject")
	}
	return p.resource("."+path, written), nil
}

// continuesPath reports whether rest, the text after the word resource,
// continues an attribute token.
func continuesPath(rest string) bool {
	if rest == "" {
		return false
	}
	r := firstRune(rest)
	return isWord(r) || r == '.' || r == '['
}

// resource returns the resource operand for path, or an [Unsupported] one
// quoting text, the operand as written, when [jsonpath.Compile] refuses the
// path.
func (p *parser) resource(path, text string) Operand {
	if _, err := jsonpath.Compile(path); err != nil {
		return Unsupported{Form: FormJSONPath, Text: text}
	}
	return Resource{Path: path}
}

// subject returns the operand for subject.name: a built-in attribute, the pass
// value inside an iterate, or a PIP named by the whole operand.
func (p *parser) subject(name string) Operand {
	switch name {
	case "id", "name", "type", "serviceAccount", "roles", "scopes", "permissions", "isM2M":
		return Subject{Attr: SubjectAttr(name)}
	}
	if strings.HasPrefix(name, "permissionScope") {
		key := ""
		if len(name) > len("permissionScope.") {
			key = name[len("permissionScope."):]
		}
		if p.iterVar != "" {
			return PassValue{Var: p.iterVar, Key: key}
		}
		return Subject{Attr: SubjectPermissionScope, Key: key}
	}
	return PIPRef{Name: "subject." + name}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
