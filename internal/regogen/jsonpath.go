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
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonpath"
	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// A resource path with brackets, .., *, ?, or a call (kind res:jsonpath) and
// without one dot at its end is read lazily: the clause that reads it binds the record that
// nc.resource_path(input.resource, path) returns, so a path only a few
// clauses reach is not evaluated for every request. Any other resource path is
// in the input before the query. The function has a name of its own because
// the record differs from the {sel, rec} of [regobuiltins]' nc.jsonpath: a
// module evaluated with that one in its place fails to compile.

// JSONPathDecl declares nc.resource_path as generated modules call it.
var JSONPathDecl = &ast.Builtin{
	Name: "nc.resource_path",
	Decl: types.NewFunction(types.Args(types.Named("doc", types.A), types.Named("path", types.S)),
		types.Named("record", types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)))),
}

// Builtins returns the built-in functions a generated module calls: those of
// [regobuiltins]; nc.resource_path, which [JSONPathRecord] answers, and which
// one query calls once per path; nc.pip.record, which reads the response of a
// GENERAL or FILTERED PIP into its record; nc.ent.record, which reads the
// answer of the entitlements service; and nc.pip, which returns a record the
// input carries.
func Builtins() []func(*rego.Rego) {
	return append(regobuiltins.Options(), pipRecordFunction(), jsonPathFunction(), pipFunction(), entRecordFunction())
}

// jsonPathFunction is the implementation of nc.resource_path. It keeps each
// record in the query's built-in cache by the identity of the document and
// the path. OPA's Memoize would key the cache by the text of the arguments,
// which prints the whole resource on every call.
func jsonPathFunction() func(*rego.Rego) {
	return rego.Function2(&rego.Function{Name: JSONPathDecl.Name, Decl: JSONPathDecl.Decl},
		func(bctx rego.BuiltinContext, doc, path *ast.Term) (*ast.Term, error) {
			p, ok := path.Value.(ast.String)
			if !ok {
				return nil, errNotAPath
			}
			// a key holds an object or a list, whose identity is a pointer;
			// another value, such as null, is not looked up
			cached := bctx.Cache != nil
			switch doc.Value.(type) {
			case *ast.Array, ast.Object:
			default:
				cached = false
			}
			key := jsonPathKey{doc.Value, string(p)}
			if cached {
				if r, ok := bctx.Cache.Get(key); ok {
					return r.(*ast.Term), nil
				}
			}
			d, err := regobuiltins.JSONOf(bctx, doc)
			if err != nil {
				return nil, err
			}
			r, err := JSONPathRecord(d, string(p))
			if err == nil && cached {
				bctx.Cache.Put(key, r)
			}
			return r, err
		})
}

// jsonPathKey keys a record of nc.resource_path in the query's built-in
// cache.
type jsonPathKey struct {
	doc  ast.Value
	path string
}

// Capabilities returns the capabilities of [regobuiltins] with
// nc.resource_path, nc.pip.record, nc.pip, and nc.ent.record added, for a
// compiler that checks generated modules.
func Capabilities() *ast.Capabilities {
	c := regobuiltins.Capabilities()
	c.Builtins = append(c.Builtins, JSONPathDecl, PIPRecordDecl, PIPDecl, EntRecordDecl)
	return c
}

type pathError string

func (e pathError) Error() string { return string(e) }

const errNotAPath = pathError("nc.resource_path: the path is not a string")

// jsonPathRef is the reference a record of nc.resource_path belongs to: a resource
// path, whose elements other than strings are one value on the right of IS
// SUBSET, and whose element tokens IS SUBSET may read.
var jsonPathRef = &Ref{Kind: spectables.KindResJSONPath, Subset: true}

// JSONPathRecord returns the value record of path over the resource doc, in
// the state [selection] gives it. doc is nil for a request without a resource
// or with a null one, and the record is then ABSENT. A selection too large
// is ERROR, which the domain of every path that can stop that way keeps
// (pathDomain), so a comparison over it is unknown, as over a failed source.
func JSONPathRecord(doc jsonvalue.Value, path string) (*ast.Term, error) {
	p, err := regobuiltins.CompilePath(path)
	if err != nil {
		return nil, err
	}
	return jsonPathRecord(doc, p).term(), nil
}

func jsonPathRecord(doc jsonvalue.Value, p *jsonpath.Path) Record {
	return record(jsonPathRef, selection(doc, p))
}
