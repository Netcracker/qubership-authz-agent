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

// Package jsonvalue holds a JSON document the way the legacy policy language
// compares it: every number keeps the exact text of the document, and every
// object keeps its members in document order.
//
// A document is a [Value]: nil, bool, [Number], string, []Value, or *[Object].
// [Decode] reads one from JSON text and keeps member order;
// [FromAST] converts an OPA value, whose object keys come sorted. [Decimal]
// compares two numbers exactly, at any number of digits and any exponent, and
// [DoubleText] prints a float64 as Java's Double.toString does.
package jsonvalue
