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
	"strconv"
	"strings"

	"authz-agent/internal/jsonvalue"
	"authz-agent/internal/legacyvalue"
)

// == between two scalars, and the element comparison of IN, CONTAINS, and
// CONTAINS ANY, compare a number with a number or a string by value and any
// other two scalars by their folded texts (ADR-0083). The relation is not
// transitive, "5.0" == 5 and 5 == "5.00" while "5.0" != "5.00", so no single
// key expresses it. A scalar has instead own tokens and match tokens, and two
// scalars are equal exactly when the own tokens of one meet the match tokens
// of the other:
//
//	scalar                            own                match
//	number of value v                 Nv                 Nv, Sv
//	string that BigDecimal reads, v   folded text, Sv    folded text, Nv
//	any other string, a boolean       folded text        folded text
//
// v is the value as [jsonvalue.Decimal.String] prints it, so 5, 5.0, and 5e0
// share it. A number beyond the range of a double has the value Infinity or
// -Infinity, which BigDecimal does not read from a string, so it equals only
// a number of the same sign. A folded text holds no ASCII capital letter
// ([legacyvalue.Fold]), so a token that starts with N or S never meets one.

// valueTokenPrefix starts the own token of a string that BigDecimal reads and
// the match token of a number; numberKeyPrefix starts the key of a number and
// the match token of such a string.
const (
	numberKeyPrefix  = "N"
	valueTokenPrefix = "S"
)

// scalarTokens are the tokens of one scalar. Its own tokens are key and
// valueKey, its match tokens key and matchKey; valueKey and matchKey are
// empty where the scalar has none.
type scalarTokens struct {
	key, valueKey, matchKey string
}

func (t scalarTokens) own() []string {
	if t.valueKey == "" {
		return []string{t.key}
	}
	return []string{t.key, t.valueKey}
}

func (t scalarTokens) match() []string {
	if t.matchKey == "" {
		return []string{t.key}
	}
	return []string{t.key, t.matchKey}
}

// numberValue returns the value of a number as the tokens print it.
type numberValue func(jsonvalue.Number) string

// inputNumberValue is the value of a number of the input: of its digits when
// it is an integer and of its Double otherwise, so 1e-400 is 0, and Infinity
// or -Infinity beyond the range of a double.
func inputNumberValue(n jsonvalue.Number) string {
	t := legacyvalue.NumberText(n)
	if d, ok := jsonvalue.ParseBigDecimal(t); ok {
		return d.String()
	}
	return t
}

// literalNumberValue is the value of a number literal and of an item of a
// literal list: the BigDecimal of its own text, so 1e-400 is not 0.
func literalNumberValue(n jsonvalue.Number) string {
	if d, ok := jsonvalue.ParseBigDecimal(string(n)); ok {
		return d.String()
	}
	return string(n)
}

func numberTokens(v string) scalarTokens {
	return scalarTokens{key: numberKeyPrefix + v, matchKey: valueTokenPrefix + v}
}

// stringTokens returns the tokens of a string whose folded text is folded; d
// is the number BigDecimal reads from it, nil for none.
func stringTokens(folded string, d *jsonvalue.Decimal) scalarTokens {
	t := scalarTokens{key: folded}
	if d != nil {
		v := d.String()
		t.valueKey, t.matchKey = valueTokenPrefix+v, numberKeyPrefix+v
	}
	return t
}

// scalarTokensOf returns the tokens of a string, a number, or a boolean; num
// gives the value of a number.
func scalarTokensOf(e jsonvalue.Value, num numberValue) scalarTokens {
	switch e := e.(type) {
	case string:
		var d *jsonvalue.Decimal
		if x, ok := jsonvalue.ParseBigDecimal(e); ok {
			d = &x
		}
		return stringTokens(legacyvalue.Fold(e), d)
	case jsonvalue.Number:
		return numberTokens(num(e))
	case bool:
		return scalarTokens{key: strconv.FormatBool(e)}
	}
	panic("regogen: not a scalar")
}

// scalarTokensOfRecord returns the tokens of the scalar e of the input from
// lv, its record, which has already read the number and the folded text.
func scalarTokensOfRecord(e jsonvalue.Value, lv legacyvalue.Record) scalarTokens {
	switch e.(type) {
	case jsonvalue.Number:
		if lv.Number != nil {
			return numberTokens(lv.Number.String())
		}
		return numberTokens(*lv.CaseKey)
	case string:
		return stringTokens(*lv.Key, lv.Number)
	}
	return scalarTokens{key: *lv.Key}
}

// listTokens returns the match and the own tokens of the elements of l that
// are not null: a scalar by its tokens, and a list or an object by its folded
// Java text, which keys, the [legacyvalue.Record.Keys] of l, holds in the
// order of l.
func listTokens(l []jsonvalue.Value, keys []string) (match, own []string) {
	match, own = []string{}, []string{}
	j := 0
	for _, e := range l {
		if e == nil {
			continue
		}
		k := keys[j]
		j++
		var t scalarTokens
		switch e := e.(type) {
		case string:
			var d *jsonvalue.Decimal
			if x, ok := jsonvalue.ParseBigDecimal(e); ok {
				d = &x
			}
			t = stringTokens(k, d)
		case jsonvalue.Number:
			t = numberTokens(inputNumberValue(e))
		default:
			t = scalarTokens{key: k}
		}
		match = append(match, t.match()...)
		own = append(own, t.own()...)
	}
	return match, own
}

// splitTokens splits tokens into those a scalar of the class string or
// scalar (a number or a boolean) can hold as its key, and those it can hold
// as its value_key: a string has a folded text as its key and an S token as
// its value_key, a number or a boolean a folded text or an N token as its key
// and no value_key.
func splitTokens(tokens []string, isString bool) (keys, values []string) {
	for _, t := range tokens {
		switch {
		case strings.HasPrefix(t, valueTokenPrefix):
			if isString {
				values = append(values, t)
			}
		case strings.HasPrefix(t, numberKeyPrefix):
			if !isString {
				keys = append(keys, t)
			}
		default:
			keys = append(keys, t)
		}
	}
	return keys, values
}

// meets reports whether the own tokens own meet the match tokens match.
func meets(own, match []string) bool {
	for _, t := range own {
		for _, m := range match {
			if t == m {
				return true
			}
		}
	}
	return false
}
