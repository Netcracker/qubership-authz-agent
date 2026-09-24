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

//go:build integration

package paritysuite

import (
	"context"
	"net/http"
)

// round13CellCase is one condition of TestRound13CellCases and the resource it
// is sent with.
type round13CellCase struct {
	id, condition string
	resource      map[string]any
}

// round13CellStates lists the operand states of TestRound13CellCases in the
// order they run; round13CellCases is keyed by them.
var round13CellStates = []string{"ABSENT", "NULL", "EMPTY_COLL", "EMPTY_SEL", "INDEX_OOB", "PIP_EMPTY", "PIP_NULL", "ERROR"}

// round13CellCases holds, per operand state, one condition for every operator
// whose answer over that state no golden fixes. A condition whose id ends in
// -alone is the operator by itself, so true tells a true operand from a false
// one or an ended rule; one ending in -or stands on the left of
// OR resource.a == 'y', so true tells a false operand from an ended rule. The
// operand states:
//
//   - ABSENT: resource.x, which the resource does not carry.
//   - NULL: resource.x is null.
//   - EMPTY_COLL: resource.x is [].
//   - EMPTY_SEL: resource.items[?(@.type=='zzz')].id over items none of which has that type.
//   - INDEX_OOB: resource.list[5] over a list of one element.
//   - PIP_EMPTY: parityNoHeaderPIP, whose header the request does not carry.
//   - PIP_NULL: a GENERAL PIP whose body is the JSON literal null.
//   - ERROR: a GENERAL PIP that answers 500.
var round13CellCases = map[string][]round13CellCase{
	"ABSENT": {
		{"ca-contains-any-alone", "resource.x CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-ca-contains-any-alone", "a": "y"}},
		{"ca-contains-any-or", "resource.x CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-ca-contains-any-or", "a": "y"}},
		{"ca-contains-or", "resource.x CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-ca-contains-or", "a": "y"}},
		{"ca-greater-or-equal-alone", "resource.x >= 5", map[string]any{"id": "r13-ca-greater-or-equal-alone", "a": "y"}},
		{"ca-greater-or-equal-or", "resource.x >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ca-greater-or-equal-or", "a": "y"}},
		{"ca-in-alone", "resource.x IN 'v', 'w'", map[string]any{"id": "r13-ca-in-alone", "a": "y"}},
		{"ca-in-or", "resource.x IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-ca-in-or", "a": "y"}},
		{"ca-is-subset-alone", "resource.x IS SUBSET 'v', 'w'", map[string]any{"id": "r13-ca-is-subset-alone", "a": "y"}},
		{"ca-is-subset-or", "resource.x IS SUBSET 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-ca-is-subset-or", "a": "y"}},
		{"ca-less-or-equal-alone", "resource.x <= 5", map[string]any{"id": "r13-ca-less-or-equal-alone", "a": "y"}},
		{"ca-less-or-equal-or", "resource.x <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ca-less-or-equal-or", "a": "y"}},
		{"ca-less-than-alone", "resource.x < 5", map[string]any{"id": "r13-ca-less-than-alone", "a": "y"}},
		{"ca-less-than-or", "resource.x < 5 OR resource.a == 'y'", map[string]any{"id": "r13-ca-less-than-or", "a": "y"}},
		{"ca-match-or", "resource.x MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-ca-match-or", "a": "y"}},
	},
	"NULL": {
		{"cx-is-not-null-or", "resource.x IS NOT NULL OR resource.a == 'y'", map[string]any{"id": "r13-cx-is-not-null-or", "a": "y", "x": nil}},
	},
	"EMPTY_COLL": {
		{"ce-contains-any-alone", "resource.x CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-ce-contains-any-alone", "a": "y", "x": []any{}}},
		{"ce-contains-any-or", "resource.x CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-ce-contains-any-or", "a": "y", "x": []any{}}},
		{"ce-contains-or", "resource.x CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-ce-contains-or", "a": "y", "x": []any{}}},
		{"ce-greater-or-equal-alone", "resource.x >= 5", map[string]any{"id": "r13-ce-greater-or-equal-alone", "a": "y", "x": []any{}}},
		{"ce-greater-or-equal-or", "resource.x >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ce-greater-or-equal-or", "a": "y", "x": []any{}}},
		{"ce-greater-than-alone", "resource.x > 5", map[string]any{"id": "r13-ce-greater-than-alone", "a": "y", "x": []any{}}},
		{"ce-greater-than-or", "resource.x > 5 OR resource.a == 'y'", map[string]any{"id": "r13-ce-greater-than-or", "a": "y", "x": []any{}}},
		{"ce-in-alone", "resource.x IN 'v', 'w'", map[string]any{"id": "r13-ce-in-alone", "a": "y", "x": []any{}}},
		{"ce-in-or", "resource.x IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-ce-in-or", "a": "y", "x": []any{}}},
		{"ce-less-or-equal-alone", "resource.x <= 5", map[string]any{"id": "r13-ce-less-or-equal-alone", "a": "y", "x": []any{}}},
		{"ce-less-or-equal-or", "resource.x <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ce-less-or-equal-or", "a": "y", "x": []any{}}},
		{"ce-less-than-alone", "resource.x < 5", map[string]any{"id": "r13-ce-less-than-alone", "a": "y", "x": []any{}}},
		{"ce-less-than-or", "resource.x < 5 OR resource.a == 'y'", map[string]any{"id": "r13-ce-less-than-or", "a": "y", "x": []any{}}},
		{"ce-match-alone", "resource.x MATCH v*", map[string]any{"id": "r13-ce-match-alone", "a": "y", "x": []any{}}},
		{"ce-match-or", "resource.x MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-ce-match-or", "a": "y", "x": []any{}}},
		{"ce-not-contains-alone", "resource.x NOT CONTAINS 'v'", map[string]any{"id": "r13-ce-not-contains-alone", "a": "y", "x": []any{}}},
		{"ce-not-contains-any-alone", "resource.x NOT CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-ce-not-contains-any-alone", "a": "y", "x": []any{}}},
		{"ce-not-in-alone", "resource.x NOT IN 'v', 'w'", map[string]any{"id": "r13-ce-not-in-alone", "a": "y", "x": []any{}}},
		{"ce-not-match-alone", "resource.x NOT MATCH v*", map[string]any{"id": "r13-ce-not-match-alone", "a": "y", "x": []any{}}},
		{"ce-not-match-or", "resource.x NOT MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-ce-not-match-or", "a": "y", "x": []any{}}},
	},
	"EMPTY_SEL": {
		{"cs-contains-any-alone", "resource.items[?(@.type=='zzz')].id CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cs-contains-any-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-contains-any-or", "resource.items[?(@.type=='zzz')].id CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cs-contains-any-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-contains-or", "resource.items[?(@.type=='zzz')].id CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-cs-contains-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-equals-alone", "resource.items[?(@.type=='zzz')].id == 'v'", map[string]any{"id": "r13-cs-equals-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-equals-or", "resource.items[?(@.type=='zzz')].id == 'v' OR resource.a == 'y'", map[string]any{"id": "r13-cs-equals-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-greater-or-equal-alone", "resource.items[?(@.type=='zzz')].id >= 5", map[string]any{"id": "r13-cs-greater-or-equal-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-greater-or-equal-or", "resource.items[?(@.type=='zzz')].id >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-cs-greater-or-equal-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-greater-than-alone", "resource.items[?(@.type=='zzz')].id > 5", map[string]any{"id": "r13-cs-greater-than-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-greater-than-or", "resource.items[?(@.type=='zzz')].id > 5 OR resource.a == 'y'", map[string]any{"id": "r13-cs-greater-than-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-in-alone", "resource.items[?(@.type=='zzz')].id IN 'v', 'w'", map[string]any{"id": "r13-cs-in-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-in-or", "resource.items[?(@.type=='zzz')].id IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cs-in-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-not-empty-alone", "resource.items[?(@.type=='zzz')].id IS NOT EMPTY", map[string]any{"id": "r13-cs-is-not-empty-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-not-empty-or", "resource.items[?(@.type=='zzz')].id IS NOT EMPTY OR resource.a == 'y'", map[string]any{"id": "r13-cs-is-not-empty-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-not-null-alone", "resource.items[?(@.type=='zzz')].id IS NOT NULL", map[string]any{"id": "r13-cs-is-not-null-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-not-null-or", "resource.items[?(@.type=='zzz')].id IS NOT NULL OR resource.a == 'y'", map[string]any{"id": "r13-cs-is-not-null-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-not-subset-alone", "resource.items[?(@.type=='zzz')].id IS NOT SUBSET 'v', 'w'", map[string]any{"id": "r13-cs-is-not-subset-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-null-alone", "resource.items[?(@.type=='zzz')].id IS NULL", map[string]any{"id": "r13-cs-is-null-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-subset-alone", "resource.items[?(@.type=='zzz')].id IS SUBSET 'v', 'w'", map[string]any{"id": "r13-cs-is-subset-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-is-subset-or", "resource.items[?(@.type=='zzz')].id IS SUBSET 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cs-is-subset-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-less-or-equal-alone", "resource.items[?(@.type=='zzz')].id <= 5", map[string]any{"id": "r13-cs-less-or-equal-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-less-or-equal-or", "resource.items[?(@.type=='zzz')].id <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-cs-less-or-equal-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-less-than-alone", "resource.items[?(@.type=='zzz')].id < 5", map[string]any{"id": "r13-cs-less-than-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-less-than-or", "resource.items[?(@.type=='zzz')].id < 5 OR resource.a == 'y'", map[string]any{"id": "r13-cs-less-than-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-match-alone", "resource.items[?(@.type=='zzz')].id MATCH v*", map[string]any{"id": "r13-cs-match-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-match-or", "resource.items[?(@.type=='zzz')].id MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-cs-match-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-not-contains-any-alone", "resource.items[?(@.type=='zzz')].id NOT CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cs-not-contains-any-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-not-equals-alone", "resource.items[?(@.type=='zzz')].id != 'v'", map[string]any{"id": "r13-cs-not-equals-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-not-in-alone", "resource.items[?(@.type=='zzz')].id NOT IN 'v', 'w'", map[string]any{"id": "r13-cs-not-in-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-not-match-alone", "resource.items[?(@.type=='zzz')].id NOT MATCH v*", map[string]any{"id": "r13-cs-not-match-alone", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
		{"cs-not-match-or", "resource.items[?(@.type=='zzz')].id NOT MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-cs-not-match-or", "a": "y", "items": []any{map[string]any{"type": "a", "id": "q"}}}},
	},
	"INDEX_OOB": {
		{"co-contains-alone", "resource.list[5] CONTAINS 'v'", map[string]any{"id": "r13-co-contains-alone", "a": "y", "list": []any{"a"}}},
		{"co-contains-any-alone", "resource.list[5] CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-co-contains-any-alone", "a": "y", "list": []any{"a"}}},
		{"co-contains-any-or", "resource.list[5] CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-contains-any-or", "a": "y", "list": []any{"a"}}},
		{"co-contains-or", "resource.list[5] CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-co-contains-or", "a": "y", "list": []any{"a"}}},
		{"co-equals-alone", "resource.list[5] == 'v'", map[string]any{"id": "r13-co-equals-alone", "a": "y", "list": []any{"a"}}},
		{"co-equals-or", "resource.list[5] == 'v' OR resource.a == 'y'", map[string]any{"id": "r13-co-equals-or", "a": "y", "list": []any{"a"}}},
		{"co-greater-or-equal-alone", "resource.list[5] >= 5", map[string]any{"id": "r13-co-greater-or-equal-alone", "a": "y", "list": []any{"a"}}},
		{"co-greater-or-equal-or", "resource.list[5] >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-co-greater-or-equal-or", "a": "y", "list": []any{"a"}}},
		{"co-greater-than-alone", "resource.list[5] > 5", map[string]any{"id": "r13-co-greater-than-alone", "a": "y", "list": []any{"a"}}},
		{"co-greater-than-or", "resource.list[5] > 5 OR resource.a == 'y'", map[string]any{"id": "r13-co-greater-than-or", "a": "y", "list": []any{"a"}}},
		{"co-in-alone", "resource.list[5] IN 'v', 'w'", map[string]any{"id": "r13-co-in-alone", "a": "y", "list": []any{"a"}}},
		{"co-in-or", "resource.list[5] IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-in-or", "a": "y", "list": []any{"a"}}},
		{"co-is-not-empty-alone", "resource.list[5] IS NOT EMPTY", map[string]any{"id": "r13-co-is-not-empty-alone", "a": "y", "list": []any{"a"}}},
		{"co-is-not-empty-or", "resource.list[5] IS NOT EMPTY OR resource.a == 'y'", map[string]any{"id": "r13-co-is-not-empty-or", "a": "y", "list": []any{"a"}}},
		{"co-is-not-null-alone", "resource.list[5] IS NOT NULL", map[string]any{"id": "r13-co-is-not-null-alone", "a": "y", "list": []any{"a"}}},
		{"co-is-not-null-or", "resource.list[5] IS NOT NULL OR resource.a == 'y'", map[string]any{"id": "r13-co-is-not-null-or", "a": "y", "list": []any{"a"}}},
		{"co-is-not-subset-alone", "resource.list[5] IS NOT SUBSET 'v', 'w'", map[string]any{"id": "r13-co-is-not-subset-alone", "a": "y", "list": []any{"a"}}},
		{"co-is-not-subset-or", "resource.list[5] IS NOT SUBSET 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-is-not-subset-or", "a": "y", "list": []any{"a"}}},
		{"co-is-null-alone", "resource.list[5] IS NULL", map[string]any{"id": "r13-co-is-null-alone", "a": "y", "list": []any{"a"}}},
		{"co-is-subset-alone", "resource.list[5] IS SUBSET 'v', 'w'", map[string]any{"id": "r13-co-is-subset-alone", "a": "y", "list": []any{"a"}}},
		{"co-is-subset-or", "resource.list[5] IS SUBSET 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-is-subset-or", "a": "y", "list": []any{"a"}}},
		{"co-less-or-equal-alone", "resource.list[5] <= 5", map[string]any{"id": "r13-co-less-or-equal-alone", "a": "y", "list": []any{"a"}}},
		{"co-less-or-equal-or", "resource.list[5] <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-co-less-or-equal-or", "a": "y", "list": []any{"a"}}},
		{"co-less-than-alone", "resource.list[5] < 5", map[string]any{"id": "r13-co-less-than-alone", "a": "y", "list": []any{"a"}}},
		{"co-less-than-or", "resource.list[5] < 5 OR resource.a == 'y'", map[string]any{"id": "r13-co-less-than-or", "a": "y", "list": []any{"a"}}},
		{"co-match-alone", "resource.list[5] MATCH v*", map[string]any{"id": "r13-co-match-alone", "a": "y", "list": []any{"a"}}},
		{"co-match-or", "resource.list[5] MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-co-match-or", "a": "y", "list": []any{"a"}}},
		{"co-not-contains-any-alone", "resource.list[5] NOT CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-co-not-contains-any-alone", "a": "y", "list": []any{"a"}}},
		{"co-not-contains-any-or", "resource.list[5] NOT CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-not-contains-any-or", "a": "y", "list": []any{"a"}}},
		{"co-not-equals-alone", "resource.list[5] != 'v'", map[string]any{"id": "r13-co-not-equals-alone", "a": "y", "list": []any{"a"}}},
		{"co-not-equals-or", "resource.list[5] != 'v' OR resource.a == 'y'", map[string]any{"id": "r13-co-not-equals-or", "a": "y", "list": []any{"a"}}},
		{"co-not-in-alone", "resource.list[5] NOT IN 'v', 'w'", map[string]any{"id": "r13-co-not-in-alone", "a": "y", "list": []any{"a"}}},
		{"co-not-in-or", "resource.list[5] NOT IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-co-not-in-or", "a": "y", "list": []any{"a"}}},
		{"co-not-match-alone", "resource.list[5] NOT MATCH v*", map[string]any{"id": "r13-co-not-match-alone", "a": "y", "list": []any{"a"}}},
		{"co-not-match-or", "resource.list[5] NOT MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-co-not-match-or", "a": "y", "list": []any{"a"}}},
	},
	"PIP_EMPTY": {
		{"ch-greater-or-equal-alone", "subject.parityNoHeader >= 5", map[string]any{"id": "r13-ch-greater-or-equal-alone", "a": "y"}},
		{"ch-greater-or-equal-or", "subject.parityNoHeader >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ch-greater-or-equal-or", "a": "y"}},
		{"ch-greater-than-alone", "subject.parityNoHeader > 5", map[string]any{"id": "r13-ch-greater-than-alone", "a": "y"}},
		{"ch-greater-than-or", "subject.parityNoHeader > 5 OR resource.a == 'y'", map[string]any{"id": "r13-ch-greater-than-or", "a": "y"}},
		{"ch-less-or-equal-alone", "subject.parityNoHeader <= 5", map[string]any{"id": "r13-ch-less-or-equal-alone", "a": "y"}},
		{"ch-less-or-equal-or", "subject.parityNoHeader <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-ch-less-or-equal-or", "a": "y"}},
	},
	"PIP_NULL": {
		{"cn-contains-alone", "subject.parityR13NullBody CONTAINS 'v'", map[string]any{"id": "r13-cn-contains-alone", "a": "y"}},
		{"cn-contains-any-alone", "subject.parityR13NullBody CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cn-contains-any-alone", "a": "y"}},
		{"cn-contains-any-or", "subject.parityR13NullBody CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cn-contains-any-or", "a": "y"}},
		{"cn-contains-or", "subject.parityR13NullBody CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-cn-contains-or", "a": "y"}},
		{"cn-equals-alone", "subject.parityR13NullBody == 'v'", map[string]any{"id": "r13-cn-equals-alone", "a": "y"}},
		{"cn-equals-or", "subject.parityR13NullBody == 'v' OR resource.a == 'y'", map[string]any{"id": "r13-cn-equals-or", "a": "y"}},
		{"cn-greater-or-equal-alone", "subject.parityR13NullBody >= 5", map[string]any{"id": "r13-cn-greater-or-equal-alone", "a": "y"}},
		{"cn-greater-or-equal-or", "subject.parityR13NullBody >= 5 OR resource.a == 'y'", map[string]any{"id": "r13-cn-greater-or-equal-or", "a": "y"}},
		{"cn-greater-than-alone", "subject.parityR13NullBody > 5", map[string]any{"id": "r13-cn-greater-than-alone", "a": "y"}},
		{"cn-greater-than-or", "subject.parityR13NullBody > 5 OR resource.a == 'y'", map[string]any{"id": "r13-cn-greater-than-or", "a": "y"}},
		{"cn-in-alone", "subject.parityR13NullBody IN 'v', 'w'", map[string]any{"id": "r13-cn-in-alone", "a": "y"}},
		{"cn-in-or", "subject.parityR13NullBody IN 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cn-in-or", "a": "y"}},
		{"cn-is-not-empty-alone", "subject.parityR13NullBody IS NOT EMPTY", map[string]any{"id": "r13-cn-is-not-empty-alone", "a": "y"}},
		{"cn-is-not-null-alone", "subject.parityR13NullBody IS NOT NULL", map[string]any{"id": "r13-cn-is-not-null-alone", "a": "y"}},
		{"cn-is-not-null-or", "subject.parityR13NullBody IS NOT NULL OR resource.a == 'y'", map[string]any{"id": "r13-cn-is-not-null-or", "a": "y"}},
		{"cn-is-not-subset-alone", "subject.parityR13NullBody IS NOT SUBSET 'v', 'w'", map[string]any{"id": "r13-cn-is-not-subset-alone", "a": "y"}},
		{"cn-is-subset-alone", "subject.parityR13NullBody IS SUBSET 'v', 'w'", map[string]any{"id": "r13-cn-is-subset-alone", "a": "y"}},
		{"cn-is-subset-or", "subject.parityR13NullBody IS SUBSET 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cn-is-subset-or", "a": "y"}},
		{"cn-less-or-equal-alone", "subject.parityR13NullBody <= 5", map[string]any{"id": "r13-cn-less-or-equal-alone", "a": "y"}},
		{"cn-less-or-equal-or", "subject.parityR13NullBody <= 5 OR resource.a == 'y'", map[string]any{"id": "r13-cn-less-or-equal-or", "a": "y"}},
		{"cn-less-than-alone", "subject.parityR13NullBody < 5", map[string]any{"id": "r13-cn-less-than-alone", "a": "y"}},
		{"cn-less-than-or", "subject.parityR13NullBody < 5 OR resource.a == 'y'", map[string]any{"id": "r13-cn-less-than-or", "a": "y"}},
		{"cn-match-alone", "subject.parityR13NullBody MATCH v*", map[string]any{"id": "r13-cn-match-alone", "a": "y"}},
		{"cn-match-or", "subject.parityR13NullBody MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-cn-match-or", "a": "y"}},
		{"cn-not-contains-alone", "subject.parityR13NullBody NOT CONTAINS 'v'", map[string]any{"id": "r13-cn-not-contains-alone", "a": "y"}},
		{"cn-not-contains-any-alone", "subject.parityR13NullBody NOT CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cn-not-contains-any-alone", "a": "y"}},
		{"cn-not-contains-any-or", "subject.parityR13NullBody NOT CONTAINS ANY 'v', 'w' OR resource.a == 'y'", map[string]any{"id": "r13-cn-not-contains-any-or", "a": "y"}},
		{"cn-not-contains-or", "subject.parityR13NullBody NOT CONTAINS 'v' OR resource.a == 'y'", map[string]any{"id": "r13-cn-not-contains-or", "a": "y"}},
		{"cn-not-in-alone", "subject.parityR13NullBody NOT IN 'v', 'w'", map[string]any{"id": "r13-cn-not-in-alone", "a": "y"}},
		{"cn-not-match-alone", "subject.parityR13NullBody NOT MATCH v*", map[string]any{"id": "r13-cn-not-match-alone", "a": "y"}},
		{"cn-not-match-or", "subject.parityR13NullBody NOT MATCH v* OR resource.a == 'y'", map[string]any{"id": "r13-cn-not-match-or", "a": "y"}},
	},
	"ERROR": {
		{"cf-contains-alone", "subject.parityR13Failing CONTAINS 'v'", map[string]any{"id": "r13-cf-contains-alone", "a": "y"}},
		{"cf-contains-any-alone", "subject.parityR13Failing CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cf-contains-any-alone", "a": "y"}},
		{"cf-equals-alone", "subject.parityR13Failing == 'v'", map[string]any{"id": "r13-cf-equals-alone", "a": "y"}},
		{"cf-greater-or-equal-alone", "subject.parityR13Failing >= 5", map[string]any{"id": "r13-cf-greater-or-equal-alone", "a": "y"}},
		{"cf-greater-than-alone", "subject.parityR13Failing > 5", map[string]any{"id": "r13-cf-greater-than-alone", "a": "y"}},
		{"cf-in-alone", "subject.parityR13Failing IN 'v', 'w'", map[string]any{"id": "r13-cf-in-alone", "a": "y"}},
		{"cf-is-empty-alone", "subject.parityR13Failing IS EMPTY", map[string]any{"id": "r13-cf-is-empty-alone", "a": "y"}},
		{"cf-is-not-empty-alone", "subject.parityR13Failing IS NOT EMPTY", map[string]any{"id": "r13-cf-is-not-empty-alone", "a": "y"}},
		{"cf-is-not-null-alone", "subject.parityR13Failing IS NOT NULL", map[string]any{"id": "r13-cf-is-not-null-alone", "a": "y"}},
		{"cf-is-not-subset-alone", "subject.parityR13Failing IS NOT SUBSET 'v', 'w'", map[string]any{"id": "r13-cf-is-not-subset-alone", "a": "y"}},
		{"cf-is-null-alone", "subject.parityR13Failing IS NULL", map[string]any{"id": "r13-cf-is-null-alone", "a": "y"}},
		{"cf-is-subset-alone", "subject.parityR13Failing IS SUBSET 'v', 'w'", map[string]any{"id": "r13-cf-is-subset-alone", "a": "y"}},
		{"cf-less-or-equal-alone", "subject.parityR13Failing <= 5", map[string]any{"id": "r13-cf-less-or-equal-alone", "a": "y"}},
		{"cf-less-than-alone", "subject.parityR13Failing < 5", map[string]any{"id": "r13-cf-less-than-alone", "a": "y"}},
		{"cf-match-alone", "subject.parityR13Failing MATCH v*", map[string]any{"id": "r13-cf-match-alone", "a": "y"}},
		{"cf-not-contains-alone", "subject.parityR13Failing NOT CONTAINS 'v'", map[string]any{"id": "r13-cf-not-contains-alone", "a": "y"}},
		{"cf-not-contains-any-alone", "subject.parityR13Failing NOT CONTAINS ANY 'v', 'w'", map[string]any{"id": "r13-cf-not-contains-any-alone", "a": "y"}},
		{"cf-not-in-alone", "subject.parityR13Failing NOT IN 'v', 'w'", map[string]any{"id": "r13-cf-not-in-alone", "a": "y"}},
		{"cf-not-match-alone", "subject.parityR13Failing NOT MATCH v*", map[string]any{"id": "r13-cf-not-match-alone", "a": "y"}},
	},
}

// round13FailingConditions put every operator over the GENERAL PIP of the ERROR
// cells, keyed by the operator.
var round13FailingConditions = []struct{ key, condition string }{
	{"equals", "subject.parityR13Failing == 'v'"},
	{"not-equals", "subject.parityR13Failing != 'v'"},
	{"less-than", "subject.parityR13Failing < 5"},
	{"less-or-equal", "subject.parityR13Failing <= 5"},
	{"greater-than", "subject.parityR13Failing > 5"},
	{"greater-or-equal", "subject.parityR13Failing >= 5"},
	{"is-null", "subject.parityR13Failing IS NULL"},
	{"is-not-null", "subject.parityR13Failing IS NOT NULL"},
	{"is-empty", "subject.parityR13Failing IS EMPTY"},
	{"is-not-empty", "subject.parityR13Failing IS NOT EMPTY"},
	{"in", "subject.parityR13Failing IN 'v', 'w'"},
	{"not-in", "subject.parityR13Failing NOT IN 'v', 'w'"},
	{"contains", "subject.parityR13Failing CONTAINS 'v'"},
	{"not-contains", "subject.parityR13Failing NOT CONTAINS 'v'"},
	{"contains-any", "subject.parityR13Failing CONTAINS ANY 'v', 'w'"},
	{"not-contains-any", "subject.parityR13Failing NOT CONTAINS ANY 'v', 'w'"},
	{"is-subset", "subject.parityR13Failing IS SUBSET 'v', 'w'"},
	{"is-not-subset", "subject.parityR13Failing IS NOT SUBSET 'v', 'w'"},
	{"match", "subject.parityR13Failing MATCH v*"},
	{"not-match", "subject.parityR13Failing NOT MATCH v*"},
}

// round13FailingPIPInADenyRuleCases builds a round13FailingPIPInADenyRuleCase
// for every condition of round13FailingConditions.
func round13FailingPIPInADenyRuleCases() []regularCase {
	failing := round13GeneralPIP("subject.parityR13Failing", round13FailingRoute)
	var cases []regularCase
	for _, c := range round13FailingConditions {
		cases = append(cases, round13FailingPIPInADenyRuleCase("r13-failing-pip-in-a-deny-rule-"+c.key, c.condition, failing))
	}
	return cases
}

// round13FailingPIPInADenyRuleCase is a PERMIT_UNLESS_DENY set of one
// PERMIT_UNLESS_DENY policy whose one DENY rule has condition, which reads pip.
func round13FailingPIPInADenyRuleCase(id, condition string, pip map[string]any) regularCase {
	b := regularBuilder{caseID: id}
	rt := regularResourceType(id)
	return regularCase{
		id:           id,
		resourceType: rt,
		pips:         []any{pip},
		uploads: []regularUpload{{externalID: "parity-" + id, sets: []any{
			b.set("set", "resourceType == '"+rt+"'", "PERMIT_UNLESS_DENY", []any{
				b.policy("reader", readerTarget, "PERMIT_UNLESS_DENY", b.rule("deny", "true", condition, "DENY", nil)),
			}, nil),
		}}},
		requests: []isolatedRequest{{name: "read", resource: map[string]any{"id": "r13-failing-pip"}}},
	}
}

// round13FailingRoute is the pip-mock route of the GENERAL PIP of the ERROR cells,
// pinned to answer 500.
const round13FailingRoute = "/api/v1/pip/r13-failing"

// round13GeneralPIP is a GENERAL PIP named name that reads route on pip-mock.
func round13GeneralPIP(name, route string) map[string]any {
	return map[string]any{
		"name": name, "url": "http://pip-mock:8090" + route, "httpMethod": "POST", "pipType": "GENERAL",
		"requestAttributes": map[string]string{"case": name}, "cacheable": false,
	}
}

// What each operator answers over each operand state in the cells of the
// operator-by-state table that no golden fixes: those where a recorded case
// cannot tell a false operand from a true one, or from an ended rule, and those
// no case reaches. round13CellCases says how each condition tells them apart.
// Every condition is one simplified policy on READ, sent once.
//
// The PIP_NULL and ERROR conditions read two GENERAL PIPs of their own, pinned
// to answer null and 500 at routes of their own, as nb-null-body-* does.
//
// A GENERAL PIP that answers 500 fails the whole answer rather than one operand
// (rf-*), and over a single policy an operand that is false, a rule that ends,
// and an answer that fails all read false. So every operator is also asked over
// that PIP on the left of OR resource.a == 'y', as cf-<operator>-or: true says
// the operand was evaluated, false that the rule ended or the answer failed.
// TestRound13FailingPIPInADenyRuleCases tells those two apart.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone.
func (s *ParitySuite) TestRound13CellCases() {
	const nullRoute, failingRoute = "/api/v1/pip/r13-null-body", round13FailingRoute
	ctx := context.Background()
	s.Require().NoError(s.pipMock.PinRoute(ctx, nullRoute, PipStubResponse{StatusCode: http.StatusOK, BodyRaw: "null"}))
	s.Require().NoError(s.pipMock.PinRoute(ctx, failingRoute, PipStubResponse{
		StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity round 13 cell case"},
	}))
	pips := map[string][]any{
		"PIP_EMPTY": {parityNoHeaderPIP},
		"PIP_NULL":  {round13GeneralPIP("subject.parityR13NullBody", nullRoute)},
		"ERROR":     {round13GeneralPIP("subject.parityR13Failing", failingRoute)},
	}
	var cases []isolatedCase
	for _, state := range round13CellStates {
		for _, c := range round13CellCases[state] {
			cases = append(cases, isolatedCase{
				id: c.id, resourceType: round13ResourceType(c.id), condition: c.condition, pips: pips[state],
				requests: []isolatedRequest{{name: "probe", resource: c.resource}},
			})
		}
	}
	for _, c := range round13FailingConditions {
		id := "cf-" + c.key + "-or"
		cases = append(cases, isolatedCase{
			id: id, resourceType: round13ResourceType(id), condition: c.condition + " OR resource.a == 'y'", pips: pips["ERROR"],
			requests: []isolatedRequest{{name: "probe", resource: map[string]any{"id": "r13-" + id, "a": "y"}}},
		})
	}
	s.runIsolatedCases(cases)
}

// Whether a GENERAL PIP that answers 500 ends only the rule that reads it or
// the whole answer, under every operator. Each case is a DENY rule over that PIP
// in a PERMIT_UNLESS_DENY policy, with no other rule: true says the operand is
// false or the rule ended alone, false that the operand holds or the answer
// failed. Beside cf-<operator>-alone and cf-<operator>-or of
// TestRound13CellCases the three answers name the outcome.
//
// The cases live in their own test function so that a recording run can be
// filtered to them and leave every golden already committed alone. Legacy
// profile only.
func (s *ParitySuite) TestRound13FailingPIPInADenyRuleCases() {
	s.Require().NoError(s.pipMock.PinRoute(context.Background(), round13FailingRoute, PipStubResponse{
		StatusCode: http.StatusInternalServerError, Body: map[string]string{"error": "parity round 13 cell case"},
	}))
	s.runRegularCases(round13FailingPIPInADenyRuleCases())
}
