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

package jsonpath

import (
	"authz-agent/internal/jsonvalue"
)

// Select stops with [KindTooLarge] once its work exceeds budgetFactor times
// the weight of the document plus budgetFloor. A path whose steps select
// nested or repeated parts of the document, such as ..key over
// {"key":{"key":...}}, selects text whose length grows with the square of the
// document's depth, or a higher power for each further .. step; the budget
// keeps the work of Select, and of a caller that writes the selection out,
// linear in the size of the document.
const (
	budgetFactor = 4
	budgetFloor  = 4096
)

// budget counts the work of one Select in the units weight measures a value
// in.
type budget struct {
	doc jsonvalue.Value
	// docWeight is the weight of doc when weighed is true, and otherwise a
	// lower bound on it: budget weighs doc only as far as the work spent
	// requires, so a path that does little work over a large document reads
	// little of it.
	docWeight int
	weighed   bool
	spent     int
}

// allowed returns the work a document of weight w allows.
func allowed(w int) int {
	return budgetFactor*w + budgetFloor
}

// charge adds n to the work spent and reports whether the work is still
// within the budget.
func (b *budget) charge(n int) bool {
	b.spent += n
	return b.admits(b.spent)
}

// admits reports whether work fits the budget of doc. Where the weight known
// so far does not admit work, it weighs doc further, at least twice as far as
// the last time, so the weighing reads about as many units as the work it
// admits.
func (b *budget) admits(work int) bool {
	for work > allowed(b.docWeight) {
		if b.weighed {
			return false
		}
		need := (work - budgetFloor + budgetFactor - 1) / budgetFactor
		bound := max(need, 2*b.docWeight)
		b.docWeight = weight(b.doc, bound)
		b.weighed = b.docWeight <= bound
	}
	return true
}

// chargeWeight charges the weight of v and reports whether the work is still
// within the budget. It reads no more of v than the budget has left.
func (b *budget) chargeWeight(v jsonvalue.Value) bool {
	for {
		left := allowed(b.docWeight) - b.spent
		w := weight(v, left)
		if w <= left {
			b.spent += w
			return true
		}
		if !b.admits(b.spent + w) {
			b.spent += w
			return false
		}
	}
}

// functionInput returns the work of a function over v: one, plus one and the
// length of the text of each number of a list, which min() and the like
// parse, plus one for each other element of a list, plus one and the length
// of each key of an object.
func functionInput(v jsonvalue.Value) int {
	n := 1
	switch x := v.(type) {
	case []jsonvalue.Value:
		for _, e := range x {
			n++
			if num, ok := e.(jsonvalue.Number); ok {
				n += len(num)
			}
		}
	case *jsonvalue.Object:
		for _, k := range x.Keys() {
			n += 1 + len(k)
		}
	}
	return n
}

// weight returns the size of v: one for each value, plus the length of each
// string, member key, and number text. It stops reading once the size exceeds
// limit and then returns a size above limit.
func weight(v jsonvalue.Value, limit int) int {
	w := 1
	switch x := v.(type) {
	case string:
		w += len(x)
	case jsonvalue.Number:
		w += len(x)
	case []jsonvalue.Value:
		for _, e := range x {
			if w > limit {
				break
			}
			w += weight(e, limit-w)
		}
	case *jsonvalue.Object:
		for _, k := range x.Keys() {
			if w > limit {
				break
			}
			m, _ := x.Get(k)
			w += len(k) + weight(m, limit-w)
		}
	}
	return w
}
