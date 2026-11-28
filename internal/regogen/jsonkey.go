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
	"errors"
	"slices"
	"strconv"
	"strings"

	"authz-agent/internal/jsonvalue"
)

// pyKey returns a text that two JSON values share exactly when Python's ==
// finds them equal after json.loads reads them: a number or a boolean by its
// numeric value at any depth, so 1, 1.0, and true are one value; a string by
// its text; a list by its elements in order; and an object by its members,
// whatever their order. The key is about as long as the value's JSON text, so
// a set of keys finds the repeats of a list in time linear in its text.
func pyKey(v jsonvalue.Value) string {
	var b strings.Builder
	writeKey(&b, v, writePyScalar)
	return b.String()
}

// typedKey returns a text that two JSON values share exactly when they have
// the same JSON type and text: a number, at any depth, by the text the
// document writes, so 5 and 5.0 are two values; a boolean as itself; and a
// list or an object member by member, an object's members in any order.
func typedKey(v jsonvalue.Value) string {
	var b strings.Builder
	writeKey(&b, v, writeTypedScalar)
	return b.String()
}

// writeKey writes the key of v: null, a string, a list, and an object in one
// form for every key, and a number or a boolean as scalar writes it. Each form
// starts with its own byte, and a string is quoted, so the keys of two values
// differ wherever their forms differ.
func writeKey(b *strings.Builder, v jsonvalue.Value, scalar func(*strings.Builder, jsonvalue.Value)) {
	switch x := v.(type) {
	case nil:
		b.WriteByte('z')
	case string:
		b.WriteString(strconv.Quote(x))
	case []jsonvalue.Value:
		b.WriteByte('[')
		for _, e := range x {
			writeKey(b, e, scalar)
			b.WriteByte(',')
		}
		b.WriteByte(']')
	case *jsonvalue.Object:
		b.WriteByte('{')
		for _, k := range slices.Sorted(slices.Values(x.Keys())) {
			m, _ := x.Get(k)
			b.WriteString(strconv.Quote(k))
			b.WriteByte(':')
			writeKey(b, m, scalar)
			b.WriteByte(',')
		}
		b.WriteByte('}')
	default:
		scalar(b, v)
	}
}

func writeTypedScalar(b *strings.Builder, v jsonvalue.Value) {
	switch x := v.(type) {
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case jsonvalue.Number:
		b.WriteByte('m')
		b.WriteString(string(x))
	}
}

func writePyScalar(b *strings.Builder, v jsonvalue.Value) {
	switch x := v.(type) {
	case bool:
		if x {
			b.WriteString("f1")
		} else {
			b.WriteString("f0")
		}
	case jsonvalue.Number:
		b.WriteString(pyNumberKey(string(x)))
	}
}

// pyNumberKey returns the key of the JSON number s as Python reads it: an
// integer literal as an exact int, any other literal as the nearest float,
// zero or infinite past the float range. A value a float holds exactly is keyed by
// that float, so the int 5 and the float 5.0 share a key, and an int no float
// holds, such as 9007199254740993, is keyed by its digits.
func pyNumberKey(s string) string {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return "x" + strconv.Quote(s)
		}
		return floatKey(f)
	}
	d, ok := jsonvalue.ParseDecimal(s)
	if !ok {
		return "x" + strconv.Quote(s)
	}
	_, _, adjusted := d.Parts()
	// A float holds every integer below 10^15, and none above 1.8e308.
	if adjusted > 308 {
		return "n" + d.String()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "n" + d.String()
	}
	if adjusted >= 15 {
		if e, ok := jsonvalue.ParseDecimal(strconv.FormatFloat(f, 'f', 0, 64)); !ok || e.Compare(d) != 0 {
			return "n" + d.String()
		}
	}
	return floatKey(f)
}

// floatKey returns the key of the float f: the shortest text that reads back
// as f, with -0.0 as 0.
func floatKey(f float64) string {
	if f == 0 {
		f = 0
	}
	return "f" + strconv.FormatFloat(f, 'g', -1, 64)
}
