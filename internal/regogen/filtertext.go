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

package regogen

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/policyir"
)

// fexpr is a predicate expression of the answer: a rule's predicate (leaf),
// its negation (not), an OR or an AND of parts, a group of groups (grp),
// which renders as groups joined by OR in their own parentheses.
type fexpr struct {
	kind  string
	term  *fterm
	parts []*fexpr
}

// fterm is the predicate of one rule with its placeholders substituted.
type fterm struct {
	// key names the rule in customFilterCondition.
	key string
	// text is the substituted template of each dialect it has; template the
	// template as written, and subst the text each placeholder became, which
	// the negation of an RSQL template reads.
	text, template map[policyir.Dialect]string
	subst          map[policyir.Dialect]map[string]string
	custom         *customTerm
}

// customTerm is a customPredicate with its parameters resolved.
type customTerm struct {
	Predicate string
	// Params holds each parameter's JSON value by name.
	Params map[string]jsonvalue.Value
}

func hasPredicate(p policyir.Predicates) bool { return len(p.Text) > 0 || p.Custom != nil }

// orOf is the OR of terms, the term alone where there is one.
func orOf(terms []*fexpr) *fexpr {
	if len(terms) == 1 {
		return terms[0]
	}
	return &fexpr{kind: "or", parts: terms}
}

// key identifies x by its structure and its predicates.
func (x *fexpr) key() string {
	if x.kind == "leaf" {
		k := "leaf:" + x.term.key + "\x00" + jsonText(x.term.textObject())
		if c := x.term.custom; c != nil {
			k += "\x00" + jsonText(c.object())
		}
		return k
	}
	parts := make([]string, len(x.parts))
	for i, p := range x.parts {
		parts[i] = p.key()
	}
	return x.kind + "(" + strings.Join(parts, "\x01") + ")"
}

func (t *fterm) textObject() *jsonvalue.Object {
	o := jsonvalue.NewObject()
	for _, d := range sortedKeys(t.text) {
		o.Set(string(d), t.text[d])
	}
	return o
}

// distinct returns xs without the repeats of an expression.
func distinct(xs []*fexpr) []*fexpr {
	seen := map[string]bool{}
	var out []*fexpr
	for _, x := range xs {
		if k := x.key(); !seen[k] {
			seen[k] = true
			out = append(out, x)
		}
	}
	return out
}

// andOf is the AND of parts, an AND among them spliced into it, a part that
// repeats another dropped, and an OR dropped where one of its operands is
// another part: x AND (x OR y) is x.
func andOf(parts []*fexpr) *fexpr {
	var flat []*fexpr
	for _, p := range parts {
		if p.kind == "and" {
			flat = append(flat, p.parts...)
		} else {
			flat = append(flat, p)
		}
	}
	flat = distinct(flat)
	keys := map[string]bool{}
	for _, p := range flat {
		keys[bare(p).key()] = true
	}
	var kept []*fexpr
	for _, p := range flat {
		if !absorbed(bare(p), keys) {
			kept = append(kept, p)
		}
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return &fexpr{kind: "and", parts: kept}
}

// bare is x without the OR of one operand that keeps a predicate in its
// parentheses.
func bare(x *fexpr) *fexpr {
	for x.kind == "or" && len(x.parts) == 1 {
		x = x.parts[0]
	}
	return x
}

// absorbed reports whether x is an OR or a group with an operand whose key is
// in keys.
func absorbed(x *fexpr, keys map[string]bool) bool {
	if x.kind != "or" && x.kind != "grp" {
		return false
	}
	for _, p := range x.parts {
		if keys[bare(p).key()] {
			return true
		}
	}
	return false
}

// negate is the negation of x by De Morgan, down to its predicates.
func negate(x *fexpr) *fexpr {
	switch x.kind {
	case "leaf":
		return &fexpr{kind: "not", parts: []*fexpr{x}}
	case "not":
		return x.parts[0]
	case "and":
		parts := make([]*fexpr, len(x.parts))
		for i, p := range x.parts {
			parts[i] = negate(p)
		}
		return &fexpr{kind: "or", parts: parts}
	}
	// or, grp
	parts := make([]*fexpr, len(x.parts))
	for i, p := range x.parts {
		parts[i] = negate(p)
	}
	return andOf(parts)
}

// The fields of the answer per dialect.
var filterFields = []struct {
	d     policyir.Dialect
	field string
}{
	{policyir.DialectQueryDSL, "filterCondition"},
	{policyir.DialectMongoDB, "mongodbFilterCondition"},
	{policyir.DialectRSQL, "rsqlFilterCondition"},
	{policyir.DialectSQL, "sqlFilterCondition"},
}

// render returns the text of x in dialect d, and false where x has none: an
// OR keeps the parts that have the dialect, which only drops rows, and an AND
// needs every part, since an operand left out would add rows the others
// exclude.
func render(x *fexpr, d policyir.Dialect) (string, bool) {
	switch x.kind {
	case "grp":
		var texts []string
		for _, g := range x.parts {
			if t, ok := render(g, d); ok {
				texts = append(texts, t)
			}
		}
		return joinGroups(texts, d)
	case "leaf":
		t, ok := x.term.text[d]
		if !ok {
			return "", false
		}
		if d == policyir.DialectMongoDB {
			return braceMongo(x.term, t), true
		}
		return t, true
	case "not":
		leaf := x.parts[0]
		inner, ok := render(leaf, d)
		if !ok {
			return "", false
		}
		switch d {
		case policyir.DialectRSQL:
			return negateRSQLTerm(leaf.term)
		case policyir.DialectSQL:
			return "NOT (" + inner + ")", true
		case policyir.DialectQueryDSL:
			return "(" + inner + ").not()", true
		}
		return negateMongoLeaf(leaf.term), true
	}
	type part struct {
		x    *fexpr
		text string
	}
	var parts []part
	for _, p := range x.parts {
		t, ok := render(p, d)
		if !ok {
			if x.kind == "and" {
				return "", false
			}
			continue
		}
		parts = append(parts, part{p, t})
	}
	switch len(parts) {
	case 0:
		return "", false
	case 1:
		return parts[0].text, true
	}
	texts := make([]string, len(parts))
	for i, p := range parts {
		texts[i] = p.text
	}
	switch d {
	case policyir.DialectRSQL, policyir.DialectSQL:
		sep := map[bool]string{true: ",", false: ";"}[x.kind == "or"]
		if d == policyir.DialectSQL {
			sep = map[bool]string{true: " OR ", false: " AND "}[x.kind == "or"]
		}
		for i, p := range parts {
			if (p.x.kind == "or" || p.x.kind == "and" || p.x.kind == "grp") && p.x.kind != x.kind ||
				d == policyir.DialectRSQL && x.kind == "and" && rsqlMayBeOr(p.text) {
				texts[i] = "(" + texts[i] + ")"
			}
		}
		return strings.Join(texts, sep), true
	case policyir.DialectQueryDSL:
		m := map[bool]string{true: ".or(", false: ".and("}[x.kind == "or"]
		acc := "(" + texts[0] + ")"
		for _, t := range texts[1:] {
			acc += m + t + ")"
		}
		return acc, true
	}
	return `{ "$` + x.kind + `": [ ` + strings.Join(texts, ", ") + " ] }", true
}

// rsqlMayBeOr reports whether the RSQL text s may be an OR at its top
// level, which an AND around it has to put in parentheses, as ; binds
// tighter than ,: the negation of an AND, or a predicate written as an OR.
// A text the tokenizer refuses, or whose parentheses do not balance, may be
// one. The text holds the values of placeholders, so it is scanned once, in
// time linear in its length, rather than parsed.
func rsqlMayBeOr(s string) bool {
	tokens, err := rsqlTokens(s)
	if err != nil {
		return true
	}
	depth := 0
	for _, t := range tokens {
		switch t.kind {
		case "LP":
			depth++
		case "RP":
			depth--
			if depth < 0 {
				return true
			}
		case "OR":
			if depth == 0 {
				return true
			}
		}
	}
	return depth != 0
}

// joinGroups joins the texts of groups by OR, each in its own parentheses,
// and returns false for none.
func joinGroups(texts []string, d policyir.Dialect) (string, bool) {
	switch len(texts) {
	case 0:
		return "", false
	case 1:
		return texts[0], true
	}
	switch d {
	case policyir.DialectRSQL:
		return "(" + strings.Join(texts, "),(") + ")", true
	case policyir.DialectSQL:
		return "(" + strings.Join(texts, ") or (") + ")", true
	case policyir.DialectQueryDSL:
		acc := "(" + texts[0] + ")"
		for _, t := range texts[1:] {
			acc += ".or(" + t + ")"
		}
		return acc, true
	}
	return `{ "$or": [ ` + strings.Join(texts, ",") + " ] }", true
}

// negateRSQLTerm is the RSQL text of the negation of t: its template
// negated, and then each placeholder replaced by the text it became, so that
// a value goes into the negation as it went into the predicate. It returns
// false where the template has no negation.
func negateRSQLTerm(t *fterm) (string, bool) {
	neg, ok := negateRSQL(t.template[policyir.DialectRSQL])
	if !ok {
		return "", false
	}
	subst := t.subst[policyir.DialectRSQL]
	return placeholderRE.ReplaceAllStringFunc(neg, func(m string) string {
		if v, ok := subst[m[2:len(m)-1]]; ok {
			return v
		}
		return m
	}), true
}

// mongoNegate maps each MongoDB comparison operator to its opposite.
var mongoNegate = map[string]string{"$eq": "$ne", "$ne": "$eq", "$in": "$nin", "$nin": "$in", "$lt": "$gte",
	"$gte": "$lt", "$gt": "$lte", "$lte": "$gt"}

// mongoTokenRE splits a MongoDB text into strings, placeholders, brackets and
// separators, bare words, and whitespace: the characters isPySpace accepts,
// as in the specification the negation follows.
var mongoTokenRE = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|\$\{[^}]*\}|[{}\[\],:]|` +
	`[^\t\n\v\f\r\x{1c}-\x{1f}\x{85}\p{Z}{}\[\],:"]+|[\t\n\v\f\r\x{1c}-\x{1f}\x{85}\p{Z}]+`)

// braceMongo wraps the MongoDB text t of a predicate of term, or of its
// negation, in the braces legacy puts around a predicate: "{ " and " }" where
// the template of the predicate substitutes a value, "{" and "}" otherwise.
func braceMongo(term *fterm, t string) string {
	if strings.Contains(term.template[policyir.DialectMongoDB], "${") {
		return "{ " + t + " }"
	}
	return "{" + t + "}"
}

// negateMongoLeaf is the MongoDB text of the negation of the predicate of
// term, braces included: its template in the legacy braces, negated by
// negateMongoText, and then each placeholder replaced by the text it became,
// as negateRSQLTerm does. A term without a MongoDB template negates its text.
func negateMongoLeaf(term *fterm) string {
	tmpl, ok := term.template[policyir.DialectMongoDB]
	if !ok {
		return negateMongoText(braceMongo(term, term.text[policyir.DialectMongoDB]))
	}
	subst := term.subst[policyir.DialectMongoDB]
	return placeholderRE.ReplaceAllStringFunc(negateMongoText(braceMongo(term, tmpl)), func(m string) string {
		if v, ok := subst[m[2:len(m)-1]]; ok {
			return v
		}
		return m
	})
}

// mongoNode is a node of the tolerant tree of a MongoDB text: an object, an
// array, or a scalar, with the byte span [start, end) of its text. Legacy's
// texts are not always JSON: an object may hold a bare object ({ { "a": 1 } })
// and a value may be a placeholder or an unquoted word.
type mongoNode struct {
	kind       byte // 'o' object, 'a' array, 's' scalar
	start, end int
	// members of an object, values of an array (with an empty key)
	items []mongoItem
}

// mongoItem is a member of an object, with the span of its quoted key and
// the key as written between the quotes, or a bare value when member is
// false.
type mongoItem struct {
	member           bool
	keyStart, keyEnd int
	key              string
	val              *mongoNode
}

type mongoToken struct {
	at   int
	text string
}

// mongoTree is the tolerant tree of s, nil where s is empty, its brackets do
// not pair, a separator or a member's value is missing or out of place, a
// token is left over, or the brackets nest deeper than [jsonvalue.MaxDepth],
// the limit of a JSON document: the text comes from a policy and is not
// bounded by the decoder of the policy around it.
func mongoTree(s string) *mongoNode {
	var toks []mongoToken
	for _, ix := range mongoTokenRE.FindAllStringIndex(s, -1) {
		t := s[ix[0]:ix[1]]
		if strings.TrimFunc(t, isPySpace) != "" {
			toks = append(toks, mongoToken{ix[0], t})
		}
	}
	pos := 0
	peek := func() string {
		if pos < len(toks) {
			return toks[pos].text
		}
		return ""
	}
	var value func(depth int) *mongoNode
	value = func(depth int) *mongoNode {
		if pos >= len(toks) {
			return nil
		}
		at, t := toks[pos].at, toks[pos].text
		switch t {
		case "{", "[":
			if depth > jsonvalue.MaxDepth {
				return nil
			}
			pos++
			n := &mongoNode{kind: 'o', start: at}
			closing := "}"
			if t == "[" {
				n.kind, closing = 'a', "]"
			}
			for peek() != closing {
				switch peek() {
				case "", ",", ":", "}", "]":
					return nil
				}
				kat, key := toks[pos].at, toks[pos].text
				if t == "{" && strings.HasPrefix(key, `"`) && pos+1 < len(toks) && toks[pos+1].text == ":" {
					pos += 2
					switch peek() {
					case "", ",", ":", "}", "]":
						return nil
					}
					v := value(depth + 1)
					if v == nil {
						return nil
					}
					n.items = append(n.items, mongoItem{member: true, keyStart: kat, keyEnd: kat + len(key),
						key: key[1 : len(key)-1], val: v})
				} else {
					v := value(depth + 1)
					if v == nil {
						return nil
					}
					n.items = append(n.items, mongoItem{val: v})
				}
				if peek() == "," {
					pos++
				}
			}
			n.end = toks[pos].at + 1
			pos++
			return n
		case "}", "]", ",", ":":
			return nil
		}
		pos++
		return &mongoNode{kind: 's', start: at, end: at + len(t)}
	}
	n := value(1)
	if n == nil || pos != len(toks) {
		return nil
	}
	return n
}

// mongoEdit replaces the bytes [start, end) of a text with text.
type mongoEdit struct {
	start, end int
	text       string
}

// negateMongoText is the negation of the MongoDB text s: an operator with an
// opposite replaced by it, $and and $or swapped with each element negated, a
// bare object inside braces negated in place, and anything else, or a text
// that has no tree ([mongoTree]), wrapped in { "$nor": [ ... ] }.
func negateMongoText(s string) string {
	var edits []mongoEdit
	if n := mongoTree(s); n != nil {
		edits = mongoNegations(n)
	} else {
		edits = []mongoEdit{{0, 0, `{ "$nor": [ `}, {len(s), len(s), " ] }"}}
	}
	// the specification applies the edits from the right; in one pass from
	// the left, two insertions at one point keep the order that gives
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start > edits[j].start
		}
		return edits[i].end > edits[j].end
	})
	slices.Reverse(edits)
	var b strings.Builder
	at := 0
	for _, e := range edits {
		b.WriteString(s[at:e.start])
		b.WriteString(e.text)
		at = e.end
	}
	b.WriteString(s[at:])
	return b.String()
}

// mongoNegations is the edits that negate the node n.
func mongoNegations(n *mongoNode) []mongoEdit {
	wrap := []mongoEdit{{n.start, n.start, `{ "$nor": [ `}, {n.end, n.end, " ] }"}}
	if n.kind != 'o' || len(n.items) != 1 {
		return wrap
	}
	it := n.items[0]
	if !it.member {
		if it.val.kind == 'o' {
			return mongoNegations(it.val)
		}
		return wrap
	}
	v := it.val
	if (it.key == "$and" || it.key == "$or") && v.kind == 'a' && len(v.items) > 0 && allObjects(v.items) {
		swapped := "$or"
		if it.key == "$or" {
			swapped = "$and"
		}
		edits := []mongoEdit{{it.keyStart + 1, it.keyEnd - 1, swapped}}
		for _, e := range v.items {
			edits = append(edits, mongoNegations(e.val)...)
		}
		return edits
	}
	if !strings.HasPrefix(it.key, "$") && v.kind == 'o' && len(v.items) == 1 && v.items[0].member {
		if op, ok := mongoNegate[v.items[0].key]; ok {
			return []mongoEdit{{v.items[0].keyStart + 1, v.items[0].keyEnd - 1, op}}
		}
	}
	return wrap
}

func allObjects(items []mongoItem) bool {
	for _, e := range items {
		if e.val.kind != 'o' {
			return false
		}
	}
	return true
}

// FilterAnswer is the answer of check/filter. Text holds the text of each
// dialect a predicate of the answer has; Custom is customFilterCondition,
// nil for none.
type FilterAnswer struct {
	Result string
	Text   map[policyir.Dialect]string
	Custom *jsonvalue.Object
}

// The values of [FilterAnswer.Result].
const (
	FilterAllow     = "ALLOW"
	FilterDeny      = "DENY"
	FilterCondition = "USE_FILTER_CONDITION"
)

// MarshalJSON writes the answer as legacy does: each field of a dialect
// without a predicate is null.
func (a FilterAnswer) MarshalJSON() ([]byte, error) {
	o := jsonvalue.NewObject()
	o.Set("calculationResult", a.Result)
	for _, f := range filterFields {
		if t, ok := a.Text[f.d]; ok {
			o.Set(f.field, t)
		} else {
			o.Set(f.field, nil)
		}
	}
	if a.Custom != nil {
		o.Set("customFilterCondition", a.Custom)
	} else {
		o.Set("customFilterCondition", nil)
	}
	return []byte(jsonText(o)), nil
}

var _ json.Marshaler = FilterAnswer{}

// filterAnswer is the answer whose allowed rows are a.
func filterAnswer(a rows) FilterAnswer {
	switch a.kind {
	case rowsAll:
		return FilterAnswer{Result: FilterAllow}
	case rowsSome:
	default:
		return FilterAnswer{Result: FilterDeny}
	}
	out := FilterAnswer{Result: FilterCondition, Text: map[policyir.Dialect]string{}}
	for _, f := range filterFields {
		var texts []string
		for _, g := range a.groups {
			if t, ok := render(g, f.d); ok {
				texts = append(texts, t)
			}
		}
		if t, ok := joinGroups(texts, f.d); ok {
			out.Text[f.d] = t
		}
	}
	var logic []jsonvalue.Value
	data := jsonvalue.NewObject()
	paths := map[string]string{}
	for _, g := range a.groups {
		namePaths(g, paths)
	}
	for _, g := range a.groups {
		if l := renderCustom(g); l != nil {
			logic = append(logic, l)
		}
		collectCustom(g, data)
	}
	switch len(logic) {
	case 0:
	case 1:
		out.Custom = customObject(logic[0], data)
	default:
		out.Custom = customObject(opObject("OR", logic), data)
	}
	if len(out.Text) == 0 && out.Custom == nil {
		// every group needs a subtraction no dialect can write
		return FilterAnswer{Result: FilterDeny}
	}
	return out
}

func customObject(logic jsonvalue.Value, data *jsonvalue.Object) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set("logic", logic)
	o.Set("data", data)
	return o
}

func opObject(op string, apply []jsonvalue.Value) *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set("op", op)
	o.Set("apply", apply)
	return o
}

// renderCustom is the logic of customFilterCondition over x, nil where x
// has none: as in render, an AND needs every part and an OR keeps the parts
// that have one.
func renderCustom(x *fexpr) jsonvalue.Value {
	switch x.kind {
	case "leaf":
		if x.term.custom == nil {
			return nil
		}
		o := jsonvalue.NewObject()
		o.Set("path", x.term.key)
		return o
	case "not":
		inner := renderCustom(x.parts[0])
		if inner == nil {
			return nil
		}
		return opObject("NOT", []jsonvalue.Value{inner})
	}
	var parts []jsonvalue.Value
	for _, p := range x.parts {
		l := renderCustom(p)
		if l == nil {
			if x.kind == "and" {
				return nil
			}
			continue
		}
		parts = append(parts, l)
	}
	switch len(parts) {
	case 0:
		return nil
	case 1:
		return parts[0]
	}
	op := "OR"
	if x.kind == "and" {
		op = "AND"
	}
	return opObject(op, parts)
}

// object is c as an entry of the data of customFilterCondition.
func (c *customTerm) object() *jsonvalue.Object {
	o := jsonvalue.NewObject()
	o.Set("predicate", c.Predicate)
	params := jsonvalue.NewObject()
	for _, k := range sortedKeys(c.Params) {
		params.Set(k, c.Params[k])
	}
	o.Set("params", params)
	return o
}

// namePaths gives each customPredicate under x a path of its own in the
// data of customFilterCondition: the key of its rule, followed by #2, #3,
// and so on where a different predicate already holds that path. Rule IDs
// are unique within a policy only, so two rules of one tenant may share
// one. paths maps each path to the predicate there, as JSON.
func namePaths(x *fexpr, paths map[string]string) {
	if x.kind != "leaf" {
		for _, p := range x.parts {
			namePaths(p, paths)
		}
		return
	}
	if x.term.custom == nil {
		return
	}
	body := jsonText(x.term.custom.object())
	path := x.term.key
	for n := 2; paths[path] != "" && paths[path] != body; n++ {
		path = fmt.Sprintf("%s#%d", x.term.key, n)
	}
	paths[path] = body
	x.term.key = path
}

func collectCustom(x *fexpr, data *jsonvalue.Object) {
	if x.kind == "leaf" {
		if c := x.term.custom; c != nil {
			data.Set(x.term.key, c.object())
		}
		return
	}
	for _, p := range x.parts {
		collectCustom(p, data)
	}
}
