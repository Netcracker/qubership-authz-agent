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

// Package policies embeds the Rego policies so that the service carries the
// decision logic it was tested with, instead of reading it from a mount.
package policies

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

//go:embed *.rego
var files embed.FS

// Modules returns the product policies keyed by file name. The unit tests
// that live next to them (`*_test.rego`) are left out: they are for `opa test`,
// not for the running service.
func Modules() (map[string]string, error) {
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		return nil, fmt.Errorf("list embedded policies: %w", err)
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		content, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read embedded policy %s: %w", name, err)
		}
		out[name] = string(content)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no policies are embedded")
	}
	return out, nil
}
