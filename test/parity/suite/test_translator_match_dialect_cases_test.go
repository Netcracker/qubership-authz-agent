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

// Which wildcard dialect MATCH speaks on a path. The agent's own condition parser
// accepts every pattern below and hands it on as a string, and four answers are
// recorded for the operator: x5-match-unquoted-wildcard has ab* matching abc, not
// matching xabc and not matching ABC, so MATCH is anchored and case-sensitive;
// a2-match-attribute-pattern has a pattern taken from an attribute answering false;
// and x34-regex-literal has /ab.*/ answering false even for a value the regex
// describes. Nothing yet says what a metacharacter does to a path separator.
//
// Every case sends a URI the pattern should select and a URI it should not, so a
// pattern access-control accepts and never evaluates reads as a column of false
// answers rather than as a dialect. md7 is the control for the whole set: its
// pattern carries no metacharacter, so a false answer on uri-equal means the
// attribute path or the operand order is wrong and no other answer in the file
// means anything.
//
// The cases live in their own test function so that a recording run can be filtered
// to them and leave every golden already committed alone.
func (s *ParitySuite) TestTranslatorMatchDialectCases() {
	s.runIsolatedCases([]isolatedCase{
		// One star between two separators. Whether it stands for exactly one
		// segment, for any number of them, or for any run of characters including
		// the separator.
		{id: "md1-star-between-segments", resourceType: "PARITY_SUITE_MATCH_MD1", condition: "resource.uri MATCH /v1/*/items", requests: []isolatedRequest{
			{name: "one-segment-in-between", resource: map[string]any{"id": "match-md1", "uri": "/v1/a/items"}},
			{name: "two-segments-in-between", resource: map[string]any{"id": "match-md1", "uri": "/v1/a/b/items"}},
			{name: "no-segment-in-between", resource: map[string]any{"id": "match-md1", "uri": "/v1/items"}},
			{name: "last-segment-differs", resource: map[string]any{"id": "match-md1", "uri": "/v1/a/other"}},
		}},
		// One star inside a segment. Whether it stops at the next separator.
		{id: "md2-star-inside-a-segment", resourceType: "PARITY_SUITE_MATCH_MD2", condition: "resource.uri MATCH /v1/it*", requests: []isolatedRequest{
			{name: "rest-of-the-same-segment", resource: map[string]any{"id": "match-md2", "uri": "/v1/items"}},
			{name: "a-further-segment", resource: map[string]any{"id": "match-md2", "uri": "/v1/items/1"}},
			{name: "another-prefix", resource: map[string]any{"id": "match-md2", "uri": "/v1/xtems"}},
		}},
		// A double star that is not the last element of the pattern.
		{id: "md3-double-star-between-segments", resourceType: "PARITY_SUITE_MATCH_MD3", condition: "resource.uri MATCH /v1/**/items", requests: []isolatedRequest{
			{name: "one-segment-in-between", resource: map[string]any{"id": "match-md3", "uri": "/v1/a/items"}},
			{name: "two-segments-in-between", resource: map[string]any{"id": "match-md3", "uri": "/v1/a/b/items"}},
			{name: "no-segment-in-between", resource: map[string]any{"id": "match-md3", "uri": "/v1/items"}},
			{name: "last-segment-differs", resource: map[string]any{"id": "match-md3", "uri": "/v1/a/other"}},
		}},
		// A trailing double star against zero segments, in both spellings of a URI
		// that stops at the prefix.
		{id: "md4-double-star-at-the-end", resourceType: "PARITY_SUITE_MATCH_MD4", condition: "resource.uri MATCH /v1/items/**", requests: []isolatedRequest{
			{name: "one-segment-below", resource: map[string]any{"id": "match-md4", "uri": "/v1/items/1"}},
			{name: "two-segments-below", resource: map[string]any{"id": "match-md4", "uri": "/v1/items/1/tags"}},
			{name: "nothing-below", resource: map[string]any{"id": "match-md4", "uri": "/v1/items"}},
			{name: "separator-and-nothing-below", resource: map[string]any{"id": "match-md4", "uri": "/v1/items/"}},
		}},
		// The single-character wildcard, on one character, two, and none.
		{id: "md5-question-mark", resourceType: "PARITY_SUITE_MATCH_MD5", condition: "resource.uri MATCH /v1/item?", requests: []isolatedRequest{
			{name: "one-character", resource: map[string]any{"id": "match-md5", "uri": "/v1/items"}},
			{name: "two-characters", resource: map[string]any{"id": "match-md5", "uri": "/v1/itemss"}},
			{name: "no-character", resource: map[string]any{"id": "match-md5", "uri": "/v1/item"}},
		}},
		// A separator at the end of the pattern. The pattern also has the shape
		// x34-regex-literal records as accepted and always false, a value between two
		// slashes, so two false answers here are equally explained by the trailing
		// separator and by that reading. md7 does not separate the two, because its
		// pattern has no trailing slash to drop.
		{id: "md6-trailing-separator-in-the-pattern", resourceType: "PARITY_SUITE_MATCH_MD6", condition: "resource.uri MATCH /v1/items/", requests: []isolatedRequest{
			{name: "uri-with-the-separator", resource: map[string]any{"id": "match-md6", "uri": "/v1/items/"}},
			{name: "uri-without-the-separator", resource: map[string]any{"id": "match-md6", "uri": "/v1/items"}},
		}},
		// A pattern with no metacharacter at all, which is the control for the file
		// and the case that decides whether such a pattern is equality. The four
		// other requests ask what equality would have to ignore: a separator at the
		// end of the URI, a query string, a longer path, and a prefix.
		{id: "md7-pattern-without-a-metacharacter", resourceType: "PARITY_SUITE_MATCH_MD7", condition: "resource.uri MATCH /v1/items", requests: []isolatedRequest{
			{name: "uri-equal", resource: map[string]any{"id": "match-md7", "uri": "/v1/items"}},
			{name: "uri-with-a-trailing-separator", resource: map[string]any{"id": "match-md7", "uri": "/v1/items/"}},
			{name: "uri-with-a-query-string", resource: map[string]any{"id": "match-md7", "uri": "/v1/items?x=1"}},
			{name: "uri-with-a-longer-path", resource: map[string]any{"id": "match-md7", "uri": "/v1/items/1"}},
			{name: "uri-with-a-prefix", resource: map[string]any{"id": "match-md7", "uri": "/api/v1/items"}},
		}},
		// An empty segment in the pattern, against a URI that has one and a URI that
		// does not.
		{id: "md8-doubled-separator", resourceType: "PARITY_SUITE_MATCH_MD8", condition: "resource.uri MATCH /v1//items", requests: []isolatedRequest{
			{name: "uri-with-both-separators", resource: map[string]any{"id": "match-md8", "uri": "/v1//items"}},
			{name: "uri-with-one-separator", resource: map[string]any{"id": "match-md8", "uri": "/v1/items"}},
		}},
		// A trailing star against a query string: whether the query is part of the
		// value the pattern sees.
		{id: "md9-star-before-a-query-string", resourceType: "PARITY_SUITE_MATCH_MD9", condition: "resource.uri MATCH /v1/items*", requests: []isolatedRequest{
			{name: "uri-with-a-query-string", resource: map[string]any{"id": "match-md9", "uri": "/v1/items?x=1"}},
			{name: "uri-without-a-query-string", resource: map[string]any{"id": "match-md9", "uri": "/v1/items"}},
			{name: "another-path-with-a-query-string", resource: map[string]any{"id": "match-md9", "uri": "/v1/other?x=1"}},
		}},
		// A percent-encoded separator inside one segment, beside the decoded form of
		// the same path. If the two answers differ, the pattern is matched against
		// the decoded value.
		{id: "md10-percent-encoded-separator", resourceType: "PARITY_SUITE_MATCH_MD10", condition: "resource.uri MATCH /v1/*", requests: []isolatedRequest{
			{name: "one-segment", resource: map[string]any{"id": "match-md10", "uri": "/v1/a"}},
			{name: "percent-encoded-separator", resource: map[string]any{"id": "match-md10", "uri": "/v1/a%2Fb"}},
			{name: "literal-separator", resource: map[string]any{"id": "match-md10", "uri": "/v1/a/b"}},
		}},
		// Case on a path. x5 records ab* against ABC as false, which settles the
		// direction where the pattern is lower-case; this asks the other direction.
		{id: "md11-uppercase-in-the-pattern", resourceType: "PARITY_SUITE_MATCH_MD11", condition: "resource.uri MATCH /V1/Items", requests: []isolatedRequest{
			{name: "uri-in-the-same-case", resource: map[string]any{"id": "match-md11", "uri": "/V1/Items"}},
			{name: "uri-in-lower-case", resource: map[string]any{"id": "match-md11", "uri": "/v1/items"}},
		}},
		// A brace placeholder, the spelling a path template uses. Whether MATCH
		// reads it as a wildcard or as five literal characters.
		{id: "md12-brace-placeholder", resourceType: "PARITY_SUITE_MATCH_MD12", condition: "resource.uri MATCH /v1/{id}/items", requests: []isolatedRequest{
			{name: "a-segment-in-place-of-the-placeholder", resource: map[string]any{"id": "match-md12", "uri": "/v1/42/items"}},
			{name: "the-braces-themselves", resource: map[string]any{"id": "match-md12", "uri": "/v1/{id}/items"}},
		}},
	})
}
