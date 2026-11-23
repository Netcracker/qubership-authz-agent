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

// Goldens converts the goldens of the parity suite between the grouped files
// under testdata/golden and a tree of one file per answer, at <key>.json.
// Run it from test/parity/suite:
//
//	go run ./tools/goldens split -out DIR
//	go run ./tools/goldens merge -in DIR [-observed]
//
// split writes every golden to DIR. merge records every <key>.json under DIR
// in the grouped files, replacing the answer of a key already recorded and
// keeping the rest; with -observed it also takes the *.observed.json sidecars
// of a one-file-per-answer tree as answers.
package main

import (
	"flag"
	"fmt"
	"os"

	paritysuite "authz-agent/test/parity/suite"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	root := "testdata/golden"
	switch os.Args[1] {
	case "split":
		fs := flag.NewFlagSet("split", flag.ExitOnError)
		fs.StringVar(&root, "root", root, "directory of the grouped golden files")
		out := fs.String("out", "", "directory to write one file per golden into")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		n, err := paritysuite.SplitGoldens(root, *out)
		exitOn(err)
		fmt.Printf("wrote %d goldens to %s\n", n, *out)
	case "merge":
		fs := flag.NewFlagSet("merge", flag.ExitOnError)
		fs.StringVar(&root, "root", root, "directory of the grouped golden files")
		in := fs.String("in", "", "directory of one file per golden, at <key>.json")
		observed := fs.Bool("observed", false, "take *.observed.json files as answers too")
		_ = fs.Parse(os.Args[2:])
		if *in == "" {
			usage()
		}
		keys, err := paritysuite.MergeGoldens(root, *in, *observed)
		exitOn(err)
		fmt.Printf("recorded %d goldens from %s in %s\n", len(keys), *in, root)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: go run ./tools/goldens split -out DIR | merge -in DIR [-observed]  (from test/parity/suite)")
	os.Exit(2)
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
