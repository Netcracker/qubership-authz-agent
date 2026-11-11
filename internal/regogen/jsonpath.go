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
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/regobuiltins"
	"authz-agent/internal/regogen/spectables"
)

// A resource path with brackets, .., *, ?, or a call (kind res:jsonpath) and
// without one dot at its end is read lazily: the clause that reads it binds
// the rule path_<var>, the record that nc.resource_path(input.resource, path,
// read) returns with the fields the module reads, so a path only a few
// clauses reach is not evaluated for every request. The projection still
// builds the record of such a path that reads an index before the query, so a
// value too big to look up fails the request whichever clauses run. Any other
// resource path is in the input before the query. The function has a name of its own because
// the record differs from the {sel, rec} of [regobuiltins]' nc.jsonpath: a
// module evaluated with that one in its place fails to compile.

// JSONPathDecl declares nc.resource_path as generated modules call it.
var JSONPathDecl = &ast.Builtin{
	Name: "nc.resource_path",
	Decl: types.NewFunction(types.Args(types.Named("doc", types.A), types.Named("path", types.S),
		types.Named("read", types.N)),
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

// pathText returns the rule that holds the record of the lazily read
// resource path of r.
func pathText(r *Ref) string {
	return fmt.Sprintf("path_%s := r if r := nc.resource_path(input.%s, %s, %d)\n\n", r.Var, memberResource,
		lit(r.Path), r.read)
}

// jsonPathFunction is the implementation of nc.resource_path. It returns the
// record the projection built for a path that reads an index, and keeps any
// other record in the query's built-in cache by the identity of the document, the
// path, and the fields read. OPA's Memoize would key the cache by the text of
// the arguments, which prints the whole resource on every call.
func jsonPathFunction() func(*rego.Rego) {
	return rego.Function3(&rego.Function{Name: JSONPathDecl.Name, Decl: JSONPathDecl.Decl},
		func(bctx rego.BuiltinContext, doc, path, read *ast.Term) (*ast.Term, error) {
			p, ok := path.Value.(ast.String)
			if !ok {
				return nil, errNotAPath
			}
			n, ok := read.Value.(ast.Number)
			if !ok {
				return nil, errNotAFieldSet
			}
			fs, ok := n.Int64()
			if !ok {
				return nil, errNotAFieldSet
			}
			// the module passes input.resource, whose records of paths with
			// an index the projection has built already
			if in, ok := bctx.Context.Value(inputKey{}).(*Input); ok {
				if r, ok := in.paths[pathKey{string(p), fieldSet(fs)}]; ok {
					return r, nil
				}
			}
			// a key holds an object or a list, whose identity is a pointer;
			// another value, such as null, is not looked up
			cached := bctx.Cache != nil
			switch doc.Value.(type) {
			case *ast.Array, ast.Object:
			default:
				cached = false
			}
			key := jsonPathKey{doc.Value, string(p), fieldSet(fs)}
			if cached {
				if r, ok := bctx.Cache.Get(key); ok {
					return r.(*ast.Term), nil
				}
			}
			d, err := regobuiltins.JSONOf(bctx, doc)
			if err != nil {
				return nil, err
			}
			r, err := jsonPathRecord(d, string(p), fieldSet(fs))
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
	read fieldSet
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

const (
	errNotAPath     = pathError("nc.resource_path: the path is not a string")
	errNotAFieldSet = pathError("nc.resource_path: the fields read are not an integer")
)

// JSONPathRecord returns the value record of path over the resource doc, in
// the state [selection] gives it. doc is nil for a request without a resource
// or with a null one, and the record is then ABSENT. A selection too large
// is ERROR, which the domain of every path that can stop that way keeps
// (pathDomain), so a comparison over it is unknown, as over a failed source.
// The record holds every field, and for a value too big to look up it
// returns a halt error with the text of the limit's error.
func JSONPathRecord(doc jsonvalue.Value, path string) (*ast.Term, error) {
	return jsonPathRecord(doc, path, 0)
}

// jsonPathRecord is [JSONPathRecord] with the fields read, every field for a
// read without fieldsKnown.
func jsonPathRecord(doc jsonvalue.Value, path string, read fieldSet) (*ast.Term, error) {
	p, err := regobuiltins.CompilePath(path)
	if err != nil {
		return nil, err
	}
	return pathRecord(&Ref{Kind: spectables.KindResJSONPath, read: read}, "resource path "+path, selection(doc, p))
}
