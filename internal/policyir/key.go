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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
)

// Key identifies the content of a [Tree]. [Tree.Key] is the only way to
// build one; the zero Key identifies no tree. Keys are comparable with ==.
type Key struct {
	sum [sha256.Size]byte
}

// Key returns the key of t. Two trees have equal keys exactly when
// [reflect.DeepEqual] reports them equal, up to a SHA-256 collision: every
// field counts, nil differs from an empty slice or map, and a string field
// holding JSON as written differs from the same value with its members in
// another order. The key does not depend on where the nodes are allocated
// or on the order a map was filled in.
func (t *Tree) Key() Key {
	var k Key
	k.sum = sha256.Sum256(appendKey(nil, reflect.ValueOf(t)))
	return k
}

// appendKey appends to b an encoding of v that, among values of the static
// type of v, is equal for two values exactly when reflect.DeepEqual reports
// them equal. Every encoding delimits itself, so the encodings of the
// fields of a struct concatenate without ambiguity.
func appendKey(b []byte, v reflect.Value) []byte {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return append(b, 'n')
		}
		return appendKey(append(b, 'p'), v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return append(b, 'n')
		}
		e := v.Elem()
		b = appendKeyString(append(b, 'i'), e.Type().PkgPath()+"."+e.Type().String())
		return appendKey(b, e)
	case reflect.Struct:
		for i := range v.NumField() {
			b = appendKey(b, v.Field(i))
		}
		return b
	case reflect.Slice:
		if v.IsNil() {
			return append(b, 'n')
		}
		b = binary.AppendUvarint(append(b, 'l'), uint64(v.Len()))
		for i := range v.Len() {
			b = appendKey(b, v.Index(i))
		}
		return b
	case reflect.Map:
		if v.IsNil() {
			return append(b, 'n')
		}
		keys := make([][]byte, 0, v.Len())
		vals := make(map[string]reflect.Value, v.Len())
		for it := v.MapRange(); it.Next(); {
			k := appendKey(nil, it.Key())
			keys = append(keys, k)
			vals[string(k)] = it.Value()
		}
		slices.SortFunc(keys, bytes.Compare)
		b = binary.AppendUvarint(append(b, 'm'), uint64(len(keys)))
		for _, k := range keys {
			b = appendKey(append(b, k...), vals[string(k)])
		}
		return b
	case reflect.String:
		return appendKeyString(b, v.String())
	case reflect.Bool:
		if v.Bool() {
			return append(b, 1)
		}
		return append(b, 0)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return binary.AppendVarint(b, v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return binary.AppendUvarint(b, v.Uint())
	default:
		panic(fmt.Sprintf("policyir: Tree.Key has no encoding for a %s", v.Type()))
	}
}

func appendKeyString(b []byte, s string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(s))), s...)
}
