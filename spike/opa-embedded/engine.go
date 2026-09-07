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

package main

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"errors"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
)

// Engine is OPA as a library: the policies and data an `opa run` would load
// from the same directories, an in-memory store the data API writes to, and
// prepared queries for the paths the decision API evaluates.
type Engine struct {
	store    storage.Store
	compiler *ast.Compiler

	mu       sync.Mutex
	prepared map[string]rego.PreparedEvalQuery
}

// newEngine loads every policy and data file under paths the way `opa run`
// does, skipping names that match ignore (the chart passes `..*` for the
// kubelet's ConfigMap symlink directories), and compiles the policies once.
func newEngine(paths []string, ignore string) (*Engine, error) {
	filter := func(_ string, info fs.FileInfo, _ int) bool {
		if ignore == "" {
			return false
		}
		matched, err := filepath.Match(ignore, info.Name())
		return err == nil && matched
	}
	result, err := loader.NewFileLoader().Filtered(paths, filter)
	if err != nil {
		return nil, fmt.Errorf("load %v: %w", paths, err)
	}
	modules := make(map[string]*ast.Module, len(result.Modules))
	for name, file := range result.Modules {
		modules[name] = file.Parsed
	}
	compiler := ast.NewCompiler()
	compiler.Compile(modules)
	if compiler.Failed() {
		return nil, fmt.Errorf("compile policies: %w", compiler.Errors)
	}
	return &Engine{
		store:    inmem.NewFromObject(result.Documents),
		compiler: compiler,
		prepared: map[string]rego.PreparedEvalQuery{},
	}, nil
}

// query builds the Rego reference for a data API path, quoting every segment
// so names with dashes ("opa-lockdown-test") stay valid.
func query(segments []string) string {
	var b strings.Builder
	b.WriteString("data")
	for _, s := range segments {
		b.WriteString("[")
		b.WriteString(strconv.Quote(s))
		b.WriteString("]")
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
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	e.prepared[q] = pq
	return pq, nil
}

// Eval evaluates data.<segments> with the given input. ok is false when the
// document is undefined, which the data API reports as an empty object. The
// non-deterministic builtin results land in ndbc for the decision log.
func (e *Engine) Eval(ctx context.Context, segments []string, input any, ndbc builtins.NDBCache) (any, bool, error) {
	pq, err := e.prepare(ctx, query(segments))
	if err != nil {
		return nil, false, err
	}
	opts := []rego.EvalOption{rego.EvalNDBuiltinCache(ndbc)}
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

// Put replaces the document at segments, creating the parents, as
// PUT /v1/data/<path> does.
func (e *Engine) Put(ctx context.Context, segments []string, value any) error {
	path := storage.Path(segments)
	return storage.Txn(ctx, e.store, storage.WriteParams, func(txn storage.Transaction) error {
		if len(path) > 1 {
			if err := storage.MakeDir(ctx, e.store, txn, path[:len(path)-1]); err != nil {
				return err
			}
		}
		return e.store.Write(ctx, txn, storage.AddOp, path, value)
	})
}

// errInvalidPatch marks a JSON Patch body the store cannot apply.
var errInvalidPatch = errors.New("invalid patch")

// patchOp is one JSON Patch operation of PATCH /v1/data/<path>.
type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// Patch applies JSON Patch operations relative to segments in one
// transaction. A missing target surfaces as a storage not-found error, which
// the handler turns into 404 the way OPA does.
func (e *Engine) Patch(ctx context.Context, segments []string, ops []patchOp) error {
	root := "/" + strings.Join(segments, "/")
	return storage.Txn(ctx, e.store, storage.WriteParams, func(txn storage.Transaction) error {
		for _, op := range ops {
			var kind storage.PatchOp
			switch op.Op {
			case "add":
				kind = storage.AddOp
			case "remove":
				kind = storage.RemoveOp
			case "replace":
				kind = storage.ReplaceOp
			default:
				return fmt.Errorf("%w: unsupported op %q", errInvalidPatch, op.Op)
			}
			path, ok := storage.ParsePathEscaped(root + op.Path)
			if !ok {
				return fmt.Errorf("%w: bad path %q", errInvalidPatch, op.Path)
			}
			if err := e.store.Write(ctx, txn, kind, path, op.Value); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get reads the document at segments; ok is false when it does not exist.
func (e *Engine) Get(ctx context.Context, segments []string) (any, bool, error) {
	v, err := storage.ReadOne(ctx, e.store, storage.Path(segments))
	if err != nil {
		if storage.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return v, true, nil
}
