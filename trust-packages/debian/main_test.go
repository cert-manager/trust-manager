/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyInputToOutput_Table(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setup       func(src string) error
		srcOverride string // when set, use a non-existent src path
		wantFiles   map[string]string
		wantErr     bool
	}{
		{
			name: "copies only json files and preserves dirs",
			setup: func(src string) error {
				if err := os.WriteFile(filepath.Join(src, "a.json"), []byte("one"), 0o600); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(src, "b.txt"), []byte("txt"), 0o600); err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(filepath.Join(src, "sub", "c.json"), []byte("three"), 0o600); err != nil {
					return err
				}
				// create a symlink (non-regular file) with .json extension which should be skipped
				if err := os.Symlink(filepath.Join(src, "a.json"), filepath.Join(src, "link.json")); err != nil {
					return err
				}
				return nil
			},
			wantFiles: map[string]string{
				"a.json":     "one",
				"sub/c.json": "three",
			},
			wantErr: false,
		},
		{
			name:        "non-existent src returns error",
			setup:       nil,
			srcOverride: "NON_EXISTENT_PATH_DO_NOT_CREATE",
			wantFiles:   nil,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var srcDir string
			dstDir := t.TempDir()

			if tc.srcOverride != "" {
				// create a parent temp dir and reference a non-existent child
				tmp := t.TempDir()
				srcDir = filepath.Join(tmp, tc.srcOverride)
			} else {
				srcDir = t.TempDir()
				if tc.setup != nil {
					if err := tc.setup(srcDir); err != nil {
						t.Fatalf("setup failed: %v", err)
					}
				}
			}

			logger := log.New(&bytes.Buffer{}, "", 0)
			err := copyInputToOutput(logger, srcDir, dstDir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for path, want := range tc.wantFiles {
				gotB, err := os.ReadFile(filepath.Join(dstDir, path))
				if err != nil {
					t.Fatalf("expected file %q missing: %v", path, err)
				}
				if string(gotB) != want {
					t.Fatalf("content mismatch %q: want %q, got %q", path, want, string(gotB))
				}
			}

			// ensure the non-json file wasn't copied
			if _, err := os.Stat(filepath.Join(dstDir, "b.txt")); !os.IsNotExist(err) {
				t.Fatalf("expected b.txt to be absent, got err=%v", err)
			}
			// ensure the non-regular .json symlink wasn't copied
			if _, err := os.Stat(filepath.Join(dstDir, "link.json")); !os.IsNotExist(err) {
				t.Fatalf("expected link.json to be absent, got err=%v", err)
			}
		})
	}
}
