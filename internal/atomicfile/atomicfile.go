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

// Package atomicfile provides WriteFile, which writes content to path via a
// temp-file rename so readers never see a partial write.
package atomicfile

import (
	"os"
	"path/filepath"
)

// WriteFile writes content to path atomically: it creates a sibling temp file
// in the same directory, flushes content, sets mode 0644, then renames into
// place.  Any existing file at path is replaced in a single atomic step.
func WriteFile(path string, content []byte) error {
	return writeFileMode(path, content, 0o644)
}

// WriteFile0600 is like WriteFile but sets mode 0600 (owner read/write only).
// Use this for files that contain credentials, such as the M2M access token.
func WriteFile0600(path string, content []byte) error {
	return writeFileMode(path, content, 0o600)
}

// writeFileMode is the shared implementation behind WriteFile and WriteFile0600.
func writeFileMode(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".atomic-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
