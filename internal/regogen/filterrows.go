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

// A condition the filter reads without the resource has a value per row. A
// leaf over the resource is true on the rows it matches; a leaf a failed
// source leaves unknown is failed on every row, and so is a leaf unknown on
// every row where its path holds a value; any other leaf has its status on
// the request on every row: true, false, or unknown. Kleene's AND and OR over
// these give the rows where the condition is true, the rows where it is
// unknown, and among them the rows where it is failed: unknown with a failed
// leaf in a disjunct that has no false leaf, as [cond.failedU] holds for the
// check. The check denies a resource whole where the condition of an
// applicable rule is failed, whatever the rule's effect and whatever its
// neighbors allow. The filter writes no text derived from a condition or a
// target (ADR-0099 R14), so it reads these sets only as no row, every row, or
// rows that depend on what the row holds, and answers DENY where the failed
// rows are not none.

// rowsF is a set of rows the leaves over the resource select, known only as
// no row, every row, or rows that depend on what the row holds. fAnd, fOr,
// and fNot keep no record of which leaf a set depends on, so a set that holds
// no row, such as a leaf AND its negation, stays rowsDepend: the filter
// then denies rows it could keep, never the reverse.
type rowsF int8

const (
	rowsFalse  rowsF = iota // no row; the zero value, which tri relies on
	rowsTrue                // every row
	rowsDepend              // the rows that depend on what the row holds
)

func fAnd(a, b rowsF) rowsF {
	switch {
	case a == rowsFalse || b == rowsFalse:
		return rowsFalse
	case a == rowsTrue:
		return b
	}
	return a
}

func fOr(a, b rowsF) rowsF {
	switch {
	case a == rowsTrue || b == rowsTrue:
		return rowsTrue
	case a == rowsFalse:
		return b
	}
	return a
}

func fNot(a rowsF) rowsF {
	switch a {
	case rowsTrue:
		return rowsFalse
	case rowsFalse:
		return rowsTrue
	}
	return rowsDepend
}

// rowsVal is a condition on the rows: where it is true, where unknown, and
// where it is unknown because a value it reads failed, which e holds as
// [cond.failedU] does for the check. e is part of u.
type rowsVal struct{ t, u, e rowsF }

// kleeneAnd is unknown where neither operand is false and one is unknown,
// and failed where neither is false and one is failed.
func kleeneAnd(x, y rowsVal) rowsVal {
	notF := fAnd(fOr(x.t, x.u), fOr(y.t, y.u))
	return rowsVal{t: fAnd(x.t, y.t), u: fAnd(notF, fOr(x.u, y.u)), e: fAnd(notF, fOr(x.e, y.e))}
}

// kleeneOr is unknown where neither operand is true and one is unknown, and
// failed where neither is true and one is failed.
func kleeneOr(x, y rowsVal) rowsVal {
	notT := fAnd(fNot(x.t), fNot(y.t))
	return rowsVal{t: fOr(x.t, y.t), u: fAnd(notT, fOr(x.u, y.u)), e: fAnd(notT, fOr(x.e, y.e))}
}
