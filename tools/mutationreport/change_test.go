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
	"strings"
	"testing"
)

// The diffs with a hunk are in the shape mutago writes into
// mutago-agentic.json: a node it mutated is printed anew, so the added lines
// can be reindented, rewrapped, or have their closing brace moved.
func TestChangeOf_FindsTheCodeAMutantChanges(t *testing.T) {
	tests := []struct {
		name string
		diff string
		want change
		ok   bool
	}{
		{"a verb of a format string", `--- Original
+++ New
@@ -229,3 +229,3 @@
 		if err := checkHTTPURL(p.Issuer); err != nil {
-			return fmt.Errorf("provider %q issuer: %w", p.ID, err)
+			return fmt.Errorf("provider %q issuer: %v", p.ID, err)
 		}
`, change{before: "%w", after: "%v"}, true},
		{"an operand that mutago rewraps", `--- Original
+++ New
@@ -334,3 +334,4 @@
 func (p Provider) takesIssuerFromToken() bool {
-	return p.Issuer == "" && p.Kubernetes && p.TokenFile != ""
+	return true &&
+	p.Kubernetes && p.TokenFile != ""
 }
`, change{before: `p.Issuer == ""`, after: "true"}, true},
		{"a statement of a loop that mutago reindents", `--- Original
+++ New
@@ -178,8 +178,8 @@
 	for i, p := range c.Providers {
-		if p.Issuer == "" {
-			continue
-		}
-		issuers[p.Issuer] = true
+	if p.Issuer == "" {
+		break
 	}
+	issuers[p.Issuer] = true
+}
 	return nil
`, change{before: "continue", after: "break"}, true},
		{"an operator that gains a character", `--- Original
+++ New
@@ -1,1 +1,1 @@
-	if len(c) > 8 {
+	if len(c) >= 8 {
`, change{before: ">", after: ">="}, true},
		{"a removed field", `--- Original
+++ New
@@ -1,1 +1,1 @@
-		return &verify.Error{Code: verify.CodeNamespaceNotAllowed, Detail: "token names no kubernetes.io namespace"}
+		return &verify.Error{Code: verify.CodeNamespaceNotAllowed}
`, change{before: `, Detail: "token names no kubernetes.io namespace"`}, true},
		{"an inserted statement", `--- Original
+++ New
@@ -1,2 +1,3 @@
 	for _, p := range ps {
+		break
 		use(p)
`, change{after: "break"}, true},
		{"a removal over two lines", `--- Original
+++ New
@@ -1,4 +1,2 @@
 	x := 1
-	log.Printf("a %d",
-		x)
 	return x
`, change{before: `log.Printf("a %d", x)`}, true},
		{"a word of a raw string", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\ts := `a b`\n+\ts := `a c`\n",
			change{before: "b", after: "c"}, true},
		{"a character literal", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tif r == 'a' {\n+\tif r == 'b' {\n",
			change{before: "a", after: "b"}, true},
		{"a statement added at the end", "--- Original\n+++ New\n@@ -1,1 +1,2 @@\n \tuse(p)\n+\tbreak\n",
			change{after: "break"}, true},
		{"a statement removed at the end", "--- Original\n+++ New\n@@ -1,2 +1,1 @@\n \tuse(p)\n-\tbreak\n",
			change{before: "break"}, true},
		{"an argument added beside one that repeats it", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tf(a)\n+\tf(a, a)\n",
			change{after: ", a"}, true},
		{"an argument removed beside one that repeats it", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tf(a, a)\n+\tf(a)\n",
			change{before: ", a"}, true},
		{"a removed string argument", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tf(\"a b\")\n+\tf()\n",
			change{before: `"a b"`}, true},
		{"a raw string made interpreted", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\ts := `a`\n+\ts := \"a\"\n",
			change{before: "`a`", after: `"a"`}, true},
		{"a string literal the hunk leaves open", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tx := \"a b\n+\tx := \"a c\n",
			change{before: "b", after: "c"}, true},
		{"a value in statements that mutago puts on lines of their own",
			"--- Original\n+++ New\n@@ -1,1 +1,2 @@\n-\tx := 1; y := 2\n+\tx := 1\n+\ty := 3\n",
			change{before: "2", after: "3"}, true},
		{"a hunk that starts at the change", "--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-a\n+b\n",
			change{before: "a", after: "b"}, true},
		{"a change in the first of two hunks",
			"--- Original\n+++ New\n@@ -1,1 +1,1 @@\n-\tx := 1\n+\tx := 2\n@@ -9,1 +9,1 @@\n-\t\ty()\n+\ty()\n",
			change{before: "1", after: "2"}, true},
		{"statements that mutago puts on lines of their own", "--- Original\n+++ New\n@@ -1,1 +1,2 @@\n-\tx := 1; y := 2\n+\tx := 1\n+\ty := 2\n",
			change{}, false},
		{"the layout alone", `--- Original
+++ New
@@ -1,3 +1,3 @@
-	if ok {
-		run()
-	}
+if ok {
+	run()
+}
`, change{}, false},
		{"a call renamed beside a comment", `--- Original
+++ New
@@ -1,1 +1,1 @@
-	run() // first
+	stop() // second
`, change{before: "run", after: "stop"}, true},
		{"a comment alone", `--- Original
+++ New
@@ -1,1 +1,1 @@
-	run() // first
+	run() // second
`, change{}, false},
		{"no hunk header", "--- Original\n+++ New\n-if ok {\n+if true {\n", change{}, false},
		{"no diff", "", change{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := changeOf(tt.diff)
			if got != tt.want || ok != tt.ok {
				t.Errorf("changeOf(%q) = %+v, %v; want %+v, %v", tt.diff, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestChangeLabel_QuotesEachSideAndCutsItOnTheConsole(t *testing.T) {
	longX, longY := strings.Repeat("x", 51), strings.Repeat("y", 51)
	cutX, cutY := strings.Repeat("x", 50)+"...", strings.Repeat("y", 50)+"..."
	tests := []struct {
		name string
		c    change
		full bool
		want string
	}{
		{"a replacement", change{before: "%w", after: "%v"}, false, "`%w` → `%v`"},
		{"a removal", change{before: "break"}, false, "removes `break`"},
		{"an insertion", change{after: "break"}, false, "adds `break`"},
		{"long sides on the console", change{before: longX, after: longY}, false, "`" + cutX + "` → `" + cutY + "`"},
		{"long sides in the file", change{before: longX, after: longY}, true, "`" + longX + "` → `" + longY + "`"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.label(tt.full); got != tt.want {
				t.Errorf("%+v.label(%v) = %q, want %q", tt.c, tt.full, got, tt.want)
			}
		})
	}
}
