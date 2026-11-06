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

// Package regobuiltins registers the built-in functions that Rego generated
// from legacy policies calls, and provides [Documents], [JSONOf], and
// [CompilePath], with which such a function reads its arguments. [All] lists
// the functions; it declares none yet.
//
// Nothing is registered globally. A compiler takes [Capabilities], a query
// takes [Options], and an OPA test runner takes the same functions through the
// regotest subpackage.
package regobuiltins

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
)

// Builtin is one built-in function: its declaration for the compiler and its
// implementation for a query.
type Builtin struct {
	Decl *ast.Builtin
	// Option registers the implementation on a query.
	Option func(*rego.Rego)
}

// All returns the built-in functions in a fixed order. It returns none yet.
func All() []Builtin {
	return nil
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

// Documents holds the JSON that terms of one query's input were built from.
// The zero value is not usable; call [NewDocuments].
//
// Pass the context [Documents.Context] returns to the query's Eval. Term must
// not run concurrently with itself or with the query.
type Documents struct {
	json map[ast.Value]jsonvalue.Value
}

// NewDocuments returns an empty Documents.
func NewDocuments() *Documents {
	return &Documents{json: map[ast.Value]jsonvalue.Value{}}
}

// Term returns the term of v. Where the term reaches the query in its input,
// as with [rego.EvalParsedInput], [JSONOf] reads the term, and each object and
// list inside it, as v: members in v's order, numbers with v's text. Term
// returns an error if v, or a value inside it, is not one of the types a
// [jsonvalue.Value] holds, such as a float64 or a map[string]any.
func (d *Documents) Term(v jsonvalue.Value) (*ast.Term, error) {
	x, err := d.value(v)
	if err != nil {
		return nil, err
	}
	return ast.NewTerm(x), nil
}

func (d *Documents) value(v jsonvalue.Value) (ast.Value, error) {
	switch x := v.(type) {
	case nil:
		return ast.Null{}, nil
	case bool:
		return ast.Boolean(x), nil
	case jsonvalue.Number:
		return ast.Number(x), nil
	case string:
		return ast.String(x), nil
	case []jsonvalue.Value:
		terms := make([]*ast.Term, len(x))
		for i, e := range x {
			ev, err := d.value(e)
			if err != nil {
				return nil, err
			}
			terms[i] = ast.NewTerm(ev)
		}
		a := ast.NewArray(terms...)
		d.json[a] = x
		return a, nil
	case *jsonvalue.Object:
		items := make([][2]*ast.Term, 0, x.Len())
		for _, k := range x.Keys() {
			e, _ := x.Get(k)
			ev, err := d.value(e)
			if err != nil {
				return nil, err
			}
			items = append(items, ast.Item(ast.StringTerm(k), ast.NewTerm(ev)))
		}
		o := ast.NewObject(items...)
		d.json[o] = x
		return o, nil
	}
	return nil, fmt.Errorf("regobuiltins: %T is not a jsonvalue.Value", v)
}

type documentsKey struct{}

// Context returns a copy of ctx that carries d.
func (d *Documents) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, documentsKey{}, d)
}

// convertedKey keys the JSON of an object or a list in the query's built-in
// cache.
type convertedKey struct{ v ast.Value }

// JSONOf returns the JSON of the argument t of a built-in function. An object
// or a list that a [Documents] in the query's context built, at any depth, is
// the JSON it was built from, also where Rego passes it inside a value of its
// own. Any other object is read in OPA's order, sorted by key. A number has
// the text OPA gives it: the text of the document for a number OPA read, and
// OPA's own form for a number it computed, so 1 + 0.0 is read as 1. Every
// object or list is converted once per query where the query has a built-in
// cache.
func JSONOf(bctx rego.BuiltinContext, t *ast.Term) (jsonvalue.Value, error) {
	var known func(ast.Value) (jsonvalue.Value, bool)
	if bctx.Context != nil {
		if d, ok := bctx.Context.Value(documentsKey{}).(*Documents); ok {
			known = func(v ast.Value) (jsonvalue.Value, bool) {
				j, ok := d.json[v]
				return j, ok
			}
		}
	}
	switch v := t.Value.(type) {
	case *ast.Array, ast.Object:
		if bctx.Cache == nil {
			return jsonvalue.FromASTKnown(v, known)
		}
		key := convertedKey{v}
		if j, ok := bctx.Cache.Get(key); ok {
			return j, nil
		}
		j, err := jsonvalue.FromASTKnown(v, known)
		if err != nil {
			return nil, err
		}
		bctx.Cache.Put(key, j)
		return j, nil
	}
	return jsonvalue.FromASTKnown(t.Value, known)
}

// maxPaths bounds the paths [CompilePath] keeps compiled. Generated code passes
// a path as a literal, so one snapshot holds far fewer; the cache empties
// when it is full, so that paths of a replaced snapshot do not crowd out the
// current one.
const maxPaths = 4096

var paths = struct {
	sync.RWMutex
	m map[string]*jsonpath.Path
}{m: map[string]*jsonpath.Path{}}

// CompilePath returns the compiled path s, from the cache where it holds s.
func CompilePath(s string) (*jsonpath.Path, error) {
	paths.RLock()
	p, ok := paths.m[s]
	paths.RUnlock()
	if ok {
		return p, nil
	}
	p, err := jsonpath.Compile(s)
	if err != nil {
		return nil, err
	}
	paths.Lock()
	if len(paths.m) >= maxPaths {
		paths.m = map[string]*jsonpath.Path{}
	}
	paths.m[s] = p
	paths.Unlock()
	return p, nil
}
