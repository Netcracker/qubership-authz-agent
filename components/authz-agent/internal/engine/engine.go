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

// Package engine evaluates the embedded Rego policies over an in-memory data
// store with the OPA library. It replaces the OPA server: policies are
// compiled once at start, data documents are written by the service itself,
// and every decision is an in-process evaluation.
package engine

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/topdown/cache"
)

// Options configure a new Engine.
type Options struct {
	// Modules are the Rego sources keyed by file name. They are compiled once.
	Modules map[string]string
	// DataDirs are directories whose JSON and YAML files seed the store the way
	// `opa run <dir>` loads them: each file's document lands at the path of its
	// directory. Rego files found there are ignored; the modules come from
	// Modules.
	DataDirs []string
	// Ignore lists file name patterns to skip in DataDirs, such as `..*` for the
	// bookkeeping entries of a Kubernetes ConfigMap mount.
	Ignore []string
}

// Engine holds the compiled policies, the store, and the prepared queries.
// It is safe for concurrent use.
type Engine struct {
	store      storage.Store
	compiler   *ast.Compiler
	queryCache cache.InterQueryCache
	valueCache cache.InterQueryValueCache
	mu         sync.Mutex
	prepared   map[string]rego.PreparedEvalQuery
}

// New compiles the modules, seeds the store from DataDirs, and sets up the
// inter-query builtin caches that `http.send` relies on for its `cache`
// option, as the OPA server does.
func New(opts Options) (*Engine, error) {
	if len(opts.Modules) == 0 {
		return nil, fmt.Errorf("no policy modules")
	}
	modules := make(map[string]*ast.Module, len(opts.Modules))
	for name, src := range opts.Modules {
		module, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return nil, fmt.Errorf("parse policy %s: %w", name, err)
		}
		modules[name] = module
	}
	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("compile policies: %w", compiler.Errors)
	}
	documents := map[string]any{}
	if len(opts.DataDirs) > 0 {
		result, err := loader.NewFileLoader().Filtered(opts.DataDirs, ignoreFilter(opts.Ignore))
		if err != nil {
			return nil, fmt.Errorf("load data from %v: %w", opts.DataDirs, err)
		}
		documents = result.Documents
	}
	return &Engine{
		store:      inmem.NewFromObject(documents),
		compiler:   compiler,
		queryCache: cache.NewInterQueryCache(nil),
		valueCache: cache.NewInterQueryValueCache(context.Background(), nil),
		prepared:   map[string]rego.PreparedEvalQuery{},
	}, nil
}

// ignoreFilter skips files and directories whose base name matches one of the
// patterns, and every Rego file, which the loader would otherwise parse.
func ignoreFilter(patterns []string) loader.Filter {
	return func(_ string, info fs.FileInfo, _ int) bool {
		name := info.Name()
		if !info.IsDir() && strings.HasSuffix(name, ".rego") {
			return true
		}
		for _, pattern := range patterns {
			if ok, _ := filepath.Match(pattern, name); ok {
				return true
			}
		}
		return false
	}
}

// Query builds the Rego reference for a data path, `data["a"]["b"]`, so that
// segments with characters outside the identifier syntax stay addressable.
func Query(segments []string) string {
	var b strings.Builder
	b.WriteString("data")
	for _, s := range segments {
		b.WriteString(`["`)
		b.WriteString(strings.ReplaceAll(s, `"`, `\"`))
		b.WriteString(`"]`)
	}
	return b.String()
}

func (e *Engine) prepare(ctx context.Context, q string) (rego.PreparedEvalQuery, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pq, ok := e.prepared[q]; ok {
		return pq, nil
	}
	pq, err := rego.New(
		rego.Query(q),
		rego.Compiler(e.compiler),
		rego.Store(e.store),
		rego.InterQueryBuiltinCache(e.queryCache),
		rego.InterQueryBuiltinValueCache(e.valueCache),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	e.prepared[q] = pq
	return pq, nil
}

// Eval evaluates the document at segments with the given input. ok is false
// when the document is undefined. ndbc, when not nil, records the results of
// the non-deterministic builtins the evaluation called, for the decision log.
func (e *Engine) Eval(ctx context.Context, segments []string, input any, ndbc builtins.NDBCache) (any, bool, error) {
	pq, err := e.prepare(ctx, Query(segments))
	if err != nil {
		return nil, false, err
	}
	opts := []rego.EvalOption{}
	if ndbc != nil {
		opts = append(opts, rego.EvalNDBuiltinCache(ndbc))
	}
	if input != nil {
		opts = append(opts, rego.EvalInput(input))
	}
	rs, err := pq.Eval(ctx, opts...)
	if err != nil {
		return nil, false, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, false, nil
	}
	return rs[0].Expressions[0].Value, true, nil
}

// Put replaces the document at segments, creating the parent documents, as
// `PUT /v1/data/<path>` does on the OPA server.
func (e *Engine) Put(ctx context.Context, segments []string, value any) error {
	path := storage.Path(clone(segments))
	return storage.Txn(ctx, e.store, storage.WriteParams, func(txn storage.Transaction) error {
		if len(path) > 1 {
			if err := storage.MakeDir(ctx, e.store, txn, path[:len(path)-1]); err != nil {
				return err
			}
		}
		return e.store.Write(ctx, txn, storage.AddOp, path, value)
	})
}

// PatchOp is one JSON Patch operation applied under a document.
type PatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// Patch applies JSON Patch operations relative to the document at segments,
// as `PATCH /v1/data/<path>` does on the OPA server. A missing target
// document fails with a storage not-found error, which IsNotFound reports.
func (e *Engine) Patch(ctx context.Context, segments []string, ops []PatchOp) error {
	root := "/" + strings.Join(clone(segments), "/")
	return storage.Txn(ctx, e.store, storage.WriteParams, func(txn storage.Transaction) error {
		for _, op := range ops {
			var storeOp storage.PatchOp
			switch op.Op {
			case "add":
				storeOp = storage.AddOp
			case "remove":
				storeOp = storage.RemoveOp
			case "replace":
				storeOp = storage.ReplaceOp
			default:
				return fmt.Errorf("unsupported patch op %q", op.Op)
			}
			path, ok := storage.ParsePathEscaped(root + op.Path)
			if !ok {
				return fmt.Errorf("invalid patch path %q", op.Path)
			}
			if err := e.store.Write(ctx, txn, storeOp, path, op.Value); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get reads the document at segments. ok is false when it does not exist.
func (e *Engine) Get(ctx context.Context, segments []string) (any, bool, error) {
	value, err := storage.ReadOne(ctx, e.store, storage.Path(clone(segments)))
	if storage.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// IsNotFound reports whether err is the store's not-found error.
func IsNotFound(err error) bool { return storage.IsNotFound(err) }

// clone copies the segments so that nothing the caller hands in, such as a
// path taken from a request buffer that the HTTP server reuses, can change
// a store key later.
func clone(segments []string) []string {
	out := make([]string, len(segments))
	for i, s := range segments {
		out[i] = strings.Clone(s)
	}
	return out
}
