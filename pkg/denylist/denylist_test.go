/*
Copyright 2026 The cert-manager Authors.

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

package denylist

import (
	"strings"
	"testing"
)

const testFingerprint = "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"

func TestLoad(t *testing.T) {
	tests := map[string]struct {
		input    string
		expError bool
		expLen   int
	}{
		"a well formed denylist is accepted": {
			input:  `{"distrusted_roots": [{"sha256": "` + testFingerprint + `", "reason": "because"}]}`,
			expLen: 1,
		},
		"lowercase and colon-separated fingerprints are accepted": {
			input:  `{"distrusted_roots": [{"sha256": "86:a1:ec:ba:08:9c:4a:8d:3b:be:27:34:c6:12:ba:34:1d:81:3e:04:3c:f9:e8:a8:62:cd:5c:57:a3:6b:be:6b", "reason": "because"}]}`,
			expLen: 1,
		},
		"invalid JSON is rejected": {
			input:    `{"distrusted_roots": [`,
			expError: true,
		},
		"an empty denylist is rejected": {
			input:    `{"distrusted_roots": []}`,
			expError: true,
		},
		"a renamed top level key is rejected": {
			input:    `{"distrustedRoots": [{"sha256": "` + testFingerprint + `", "reason": "because"}]}`,
			expError: true,
		},
		"an unknown entry field is rejected": {
			input:    `{"distrusted_roots": [{"sha256": "` + testFingerprint + `", "reason": "because", "name": "something"}]}`,
			expError: true,
		},
		"a truncated fingerprint is rejected": {
			input:    `{"distrusted_roots": [{"sha256": "86A1ECBA", "reason": "because"}]}`,
			expError: true,
		},
		"a non-hex fingerprint is rejected": {
			input:    `{"distrusted_roots": [{"sha256": "` + strings.Repeat("z", 64) + `", "reason": "because"}]}`,
			expError: true,
		},
		"an empty reason is rejected": {
			input:    `{"distrusted_roots": [{"sha256": "` + testFingerprint + `", "reason": "  "}]}`,
			expError: true,
		},
		"a duplicate fingerprint is rejected": {
			input: `{"distrusted_roots": [
				{"sha256": "` + testFingerprint + `", "reason": "because"},
				{"sha256": "` + strings.ToLower(testFingerprint) + `", "reason": "because, again"}
			]}`,
			expError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dl, err := Load(strings.NewReader(test.input))
			if (err != nil) != test.expError {
				t.Fatalf("expError=%v, got err=%v", test.expError, err)
			}

			if test.expError {
				return
			}

			if dl.Len() != test.expLen {
				t.Errorf("expected %d entries, got %d", test.expLen, dl.Len())
			}

			fingerprint, err := ParseFingerprint(testFingerprint)
			if err != nil {
				t.Fatalf("unexpected error parsing test fingerprint: %v", err)
			}

			if _, found := dl.Lookup(fingerprint); !found {
				t.Errorf("expected the test fingerprint to be in the denylist")
			}
		})
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(t.TempDir() + "/does-not-exist.json"); err == nil {
		t.Error("expected an error loading a missing denylist, got none")
	}
}

func TestFingerprintString(t *testing.T) {
	fingerprint, err := ParseFingerprint("86:a1:ec:ba:08:9c:4a:8d:3b:be:27:34:c6:12:ba:34:1d:81:3e:04:3c:f9:e8:a8:62:cd:5c:57:a3:6b:be:6b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := fingerprint.String(); got != testFingerprint {
		t.Errorf("expected %s, got %s", testFingerprint, got)
	}
}
