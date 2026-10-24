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

// Package regobuiltins provides the built-in functions that Rego generated
// from legacy policies calls where Rego cannot reproduce Java:
//
//   - nc.value(v) returns the value record of v, the object
//     [legacyvalue.Record.Term] describes, for a value that comes from a PIP
//     response rather than from the input.
//   - nc.decimal.compare(a, b) returns -1, 0, or 1 as a is less than, equal
//     to, or greater than b, exactly. a and b are numbers: the n of a record
//     or a number literal. Generated code calls it where a record has nl set.
//   - nc.jsonpath(doc, path) applies a path of the subset [jsonpath] accepts,
//     without the leading $, and returns {"sel": kind, "rec": record}, where
//     kind is a [jsonpath.Kind] and rec, present for kinds one and many, is
//     the record of the selected value or of the list of selected values.
//
// Nothing is registered globally. A compiler takes [Capabilities], a query
// takes [Options], and an OPA test runner takes the same functions through the
// regotest subpackage.
//
// nc.value and nc.jsonpath see an object in OPA's order, sorted by key, so the
// Java text of an object with two or more members, [*] over an object, ..key,
// and keys() follow that order rather than the document's. Go code that holds
// the raw JSON builds the record with [jsonvalue.Decode] instead.
//
// Each function returns an error for an argument of the wrong type, and
// nc.jsonpath for a path outside the subset; OPA then leaves the call
// undefined, or fails the query under strict built-in errors.
package regobuiltins

import (
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
)

// Builtin is one built-in function: its declaration for the compiler and its
// implementation for a query.
type Builtin struct {
	Decl *ast.Builtin
	// Option registers the implementation on a query.
	Option func(*rego.Rego)
}

var record = types.NewObject(nil, types.NewDynamicProperty(types.S, types.A))

var (
	valueDecl = &ast.Builtin{
		Name: "nc.value",
		Decl: types.NewFunction(types.Args(types.Named("v", types.A)), types.Named("record", record)),
	}
	compareDecl = &ast.Builtin{
		Name: "nc.decimal.compare",
		Decl: types.NewFunction(
			types.Args(types.Named("a", types.N), types.Named("b", types.N)),
			types.Named("result", types.N)),
	}
	jsonpathDecl = &ast.Builtin{
		Name: "nc.jsonpath",
		Decl: types.NewFunction(types.Args(types.Named("doc", types.A), types.Named("path", types.S)),
			types.Named("selection", record)),
	}
)

// All returns the built-in functions in a fixed order.
func All() []Builtin {
	return []Builtin{
		{valueDecl, rego.Function1(function(valueDecl), value)},
		{compareDecl, rego.Function2(function(compareDecl), compare)},
		{jsonpathDecl, rego.Function2(function(jsonpathDecl), selectPath)},
	}
}

func function(b *ast.Builtin) *rego.Function {
	return &rego.Function{Name: b.Name, Decl: b.Decl}
}

// Capabilities returns the capabilities of the linked OPA version with the
// built-in functions added, for a compiler that checks generated modules.
func Capabilities() *ast.Capabilities {
	c := ast.CapabilitiesForThisVersion()
	for _, b := range All() {
		c.Builtins = append(c.Builtins, b.Decl)
	}
	return c
}

// Options returns the options that register the implementations on a query.
func Options() []func(*rego.Rego) {
	all := All()
	opts := make([]func(*rego.Rego), len(all))
	for i, b := range all {
		opts[i] = b.Option
	}
	return opts
}

func value(_ rego.BuiltinContext, v *ast.Term) (*ast.Term, error) {
	lv, err := jsonvalue.FromAST(v.Value)
	if err != nil {
		return nil, err
	}
	return legacyvalue.Of(lv).Term(), nil
}

func compare(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {
	x, err := decimalOf(a)
	if err != nil {
		return nil, err
	}
	y, err := decimalOf(b)
	if err != nil {
		return nil, err
	}
	return ast.InternedTerm(x.Compare(y)), nil
}

// decimalOf reads a number argument. A string is refused: a string becomes a
// number only through the n of its record, which reads it as BigDecimal does.
func decimalOf(t *ast.Term) (jsonvalue.Decimal, error) {
	v, ok := t.Value.(ast.Number)
	if !ok {
		return jsonvalue.Decimal{}, fmt.Errorf("nc.decimal.compare: %v is not a number", t)
	}
	d, ok := jsonvalue.ParseDecimal(string(v))
	if !ok {
		return jsonvalue.Decimal{}, fmt.Errorf("nc.decimal.compare: %s is not a decimal number", v)
	}
	return d, nil
}

func selectPath(_ rego.BuiltinContext, doc, path *ast.Term) (*ast.Term, error) {
	ps, ok := path.Value.(ast.String)
	if !ok {
		return nil, fmt.Errorf("nc.jsonpath: path %v is not a string", path)
	}
	p, err := jsonpath.Compile(string(ps))
	if err != nil {
		return nil, err
	}
	lv, err := jsonvalue.FromAST(doc.Value)
	if err != nil {
		return nil, err
	}
	r := p.Select(lv)
	obj := ast.NewObject(ast.Item(ast.InternedTerm("sel"), ast.StringTerm(string(r.Kind))))
	if r.Kind == jsonpath.KindOne || r.Kind == jsonpath.KindMany {
		obj.Insert(ast.InternedTerm("rec"), legacyvalue.Of(r.Value).Term())
	}
	return ast.NewTerm(obj), nil
}
