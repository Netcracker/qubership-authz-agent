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
	"reflect"
	"slices"
	"strings"
	"testing"
)

// keySeeds are the trees the twin property starts from, each built anew by
// every call.
func keySeeds() map[string]func(t *testing.T) *Tree {
	return map[string]func(t *testing.T) *Tree{
		"every kind": everyKindTree,
		"valid parts": func(t *testing.T) *Tree {
			p := validParts()
			tree, err := NewTree(p.simplified, p.sets, p.pips)
			if err != nil {
				t.Fatal(err)
			}
			return tree
		},
	}
}

// twinStep is one step of a path from the root of a tree: into a struct
// field ('f'), a slice element ('e'), the target of a pointer ('p'), or the
// value of an interface ('i').
type twinStep struct {
	kind byte
	i    int
}

// twinSite is a value reachable from the root of a seed, with a label that
// names it.
type twinSite struct {
	path  []twinStep
	label string
	value reflect.Value
}

// twinSites returns v and every value reachable from it, except the entries
// of a map, which [twinEdits] edits as part of the map. A struct field that
// reflection cannot set fails t, since no twin could differ in it.
func twinSites(t *testing.T, v reflect.Value, path []twinStep, label string) []twinSite {
	sites := []twinSite{{path: slices.Clone(path), label: label, value: v}}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			sites = append(sites, twinSites(t, v.Elem(), append(path, twinStep{'p', 0}), label)...)
		}
	case reflect.Interface:
		if !v.IsNil() {
			sites = append(sites, twinSites(t, v.Elem(), append(path, twinStep{'i', 0}),
				label+"("+v.Elem().Type().Name()+")")...)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() {
				t.Errorf("%s.%s is unexported, and no twin of the tree can differ in it", v.Type(), f.Name)
				continue
			}
			sites = append(sites, twinSites(t, v.Field(i), append(path, twinStep{'f', i}), label+"."+f.Name)...)
		}
	case reflect.Slice:
		for i := range v.Len() {
			sites = append(sites, twinSites(t, v.Index(i), append(path, twinStep{'e', i}),
				fmt.Sprintf("%s[%d]", label, i))...)
		}
	}
	return sites
}

// twinEdits returns the edits of a value like v, each of which leaves a
// value that reflect.DeepEqual tells from v, by a label that names it. impls
// maps an interface type to the dynamic types the seeds hold in it, so that
// an interface value can turn into another of them.
func twinEdits(v reflect.Value, impls map[reflect.Type][]reflect.Type) map[string]func(reflect.Value) {
	edits := map[string]func(reflect.Value){}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			edits["nil -> new"] = func(x reflect.Value) { x.Set(reflect.New(x.Type().Elem())) }
		} else {
			edits["-> nil"] = func(x reflect.Value) { x.Set(reflect.Zero(x.Type())) }
		}
	case reflect.Interface:
		if !v.IsNil() {
			edits["-> nil"] = func(x reflect.Value) { x.Set(reflect.Zero(x.Type())) }
			for _, other := range impls[v.Type()] {
				if other != v.Elem().Type() {
					edits["-> "+other.Name()+"{}"] = func(x reflect.Value) { x.Set(reflect.Zero(other)) }
				}
			}
		}
	case reflect.Slice:
		switch {
		case v.IsNil():
			edits["nil -> []"] = func(x reflect.Value) { x.Set(reflect.MakeSlice(x.Type(), 0, 0)) }
		case v.Len() == 0:
			edits["[] -> nil"] = func(x reflect.Value) { x.Set(reflect.Zero(x.Type())) }
		default:
			edits["-> nil"] = func(x reflect.Value) { x.Set(reflect.Zero(x.Type())) }
			edits["drop the last"] = func(x reflect.Value) { x.Set(x.Slice(0, x.Len()-1)) }
		}
	case reflect.Map:
		if v.IsNil() {
			edits["nil -> {}"] = func(x reflect.Value) { x.Set(reflect.MakeMap(x.Type())) }
			break
		}
		edits["-> nil"] = func(x reflect.Value) { x.Set(reflect.Zero(x.Type())) }
		added := reflect.ValueOf("added").Convert(v.Type().Key())
		edits["add a key"] = editedMap(func(m reflect.Value) { m.SetMapIndex(added, reflect.Zero(m.Type().Elem())) })
		for _, k := range v.MapKeys() {
			edits[fmt.Sprintf("drop key %v", k)] = editedMap(func(m reflect.Value) { m.SetMapIndex(k, reflect.Value{}) })
			if v.Type().Elem().Kind() == reflect.String {
				edits[fmt.Sprintf("key %v + \"x\"", k)] = editedMap(func(m reflect.Value) {
					m.SetMapIndex(k, reflect.ValueOf(m.MapIndex(k).String()+"x").Convert(m.Type().Elem()))
				})
			}
		}
	case reflect.String:
		if v.String() == "" {
			edits[`"" -> "x"`] = func(x reflect.Value) { x.SetString("x") }
		} else {
			edits[`-> ""`] = func(x reflect.Value) { x.SetString("") }
			edits[`+ "x"`] = func(x reflect.Value) { x.SetString(x.String() + "x") }
		}
	case reflect.Bool:
		edits["flip"] = func(x reflect.Value) { x.SetBool(!x.Bool()) }
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		edits["+1"] = func(x reflect.Value) { x.SetInt(x.Int() + 1) }
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		edits["+1"] = func(x reflect.Value) { x.SetUint(x.Uint() + 1) }
	}
	return edits
}

// editedMap returns an edit that replaces a map with a copy that edit
// changed, so that the twin shares no map with anything.
func editedMap(edit func(reflect.Value)) func(reflect.Value) {
	return func(x reflect.Value) {
		m := reflect.MakeMap(x.Type())
		for it := x.MapRange(); it.Next(); {
			m.SetMapIndex(it.Key(), it.Value())
		}
		edit(m)
		x.Set(m)
	}
}

// applyAt applies edit to the value at path from v. A value inside an
// interface cannot be set in place, so it is copied, edited, and stored back.
func applyAt(v reflect.Value, path []twinStep, edit func(reflect.Value)) {
	if len(path) == 0 {
		edit(v)
		return
	}
	switch s := path[0]; s.kind {
	case 'f':
		applyAt(v.Field(s.i), path[1:], edit)
	case 'e':
		applyAt(v.Index(s.i), path[1:], edit)
	case 'p':
		applyAt(v.Elem(), path[1:], edit)
	case 'i':
		c := reflect.New(v.Elem().Type()).Elem()
		c.Set(v.Elem())
		applyAt(c, path[1:], edit)
		v.Set(c)
	}
}

// A twin of a tree that differs from it in one value anywhere has another
// key. Reflection finds the values, so a field added to a node of the tree
// is edited here without a change to this test, and a value of a kind this
// test has no edit for fails it.
func TestTreeKeyTellsEveryOneValueTwinFromItsSeed(t *testing.T) {
	t.Parallel()
	seeds := keySeeds()
	impls := map[reflect.Type][]reflect.Type{}
	for _, seed := range seeds {
		for _, s := range twinSites(t, reflect.ValueOf(seed(t)).Elem(), nil, "tree") {
			if s.value.Kind() == reflect.Interface && !s.value.IsNil() &&
				!slices.Contains(impls[s.value.Type()], s.value.Elem().Type()) {
				impls[s.value.Type()] = append(impls[s.value.Type()], s.value.Elem().Type())
			}
		}
	}
	twins := 0
	for name, seed := range seeds {
		base := seed(t)
		baseKey := base.Key()
		for _, s := range twinSites(t, reflect.ValueOf(base).Elem(), nil, "tree") {
			edits := twinEdits(s.value, impls)
			switch k := s.value.Kind(); {
			case k == reflect.Map && s.value.Type().Elem().Kind() != reflect.String:
				t.Errorf("%s: %s is a map of %s, whose values no edit changes", name, s.label, s.value.Type().Elem())
			case len(edits) == 0 && k != reflect.Struct && (k != reflect.Interface || !s.value.IsNil()):
				t.Errorf("%s: %s is a %s, for which there is no edit", name, s.label, s.value.Type())
			}
			for e, edit := range edits {
				twin := seed(t)
				applyAt(reflect.ValueOf(twin).Elem(), s.path, edit)
				if reflect.DeepEqual(base, twin) {
					t.Fatalf("%s: the edit %s of %s leaves the tree as it was", name, e, s.label)
				}
				twins++
				if twin.Key() == baseKey {
					t.Errorf("%s: Key of the twin with %s %s equals the key of the seed", name, s.label, e)
				}
			}
		}
	}
	t.Logf("%d one-value twins", twins)
}

// deepCopy returns a copy of v that shares no pointer, slice, or map with
// it, and whose maps are filled in reverse key order.
func deepCopy(v reflect.Value) reflect.Value {
	c := reflect.New(v.Type()).Elem()
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			c.Set(deepCopy(v.Elem()).Addr())
		}
	case reflect.Interface:
		if !v.IsNil() {
			c.Set(deepCopy(v.Elem()))
		}
	case reflect.Struct:
		for i := range v.NumField() {
			c.Field(i).Set(deepCopy(v.Field(i)))
		}
	case reflect.Slice:
		if !v.IsNil() {
			c.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Len()))
			for i := range v.Len() {
				c.Index(i).Set(deepCopy(v.Index(i)))
			}
		}
	case reflect.Map:
		if !v.IsNil() {
			c.Set(reflect.MakeMap(v.Type()))
			keys := v.MapKeys()
			slices.SortFunc(keys, func(a, b reflect.Value) int { return strings.Compare(b.String(), a.String()) })
			for _, k := range keys {
				c.SetMapIndex(k, deepCopy(v.MapIndex(k)))
			}
		}
	default:
		c.Set(v)
	}
	return c
}

// A copy of a tree in new memory has the key of the tree, so a load whose
// export is unchanged keeps its snapshots.
func TestTreeKeyOfACopyInNewMemoryIsTheSame(t *testing.T) {
	t.Parallel()
	for name, seed := range keySeeds() {
		tree := seed(t)
		cp := deepCopy(reflect.ValueOf(tree)).Interface().(*Tree)
		if cp == tree || cp.PIPs[0] == tree.PIPs[0] {
			t.Fatalf("%s: the copy shares nodes with the tree", name)
		}
		if cp.Key() != tree.Key() {
			t.Errorf("%s: Key of a copy in new memory differs from the key of the tree", name)
		}
	}
}
