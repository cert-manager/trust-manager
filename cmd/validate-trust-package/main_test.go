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

package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cert-manager/trust-manager/pkg/denylist"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func fingerprintOf(t *testing.T, certPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("invalid test data: failed to decode PEM")
	}

	return denylist.FingerprintCert(block.Bytes).String()
}

func writeDenylist(t *testing.T, fingerprints ...string) string {
	t.Helper()

	entries := make([]string, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		entries = append(entries, `{"sha256": "`+fingerprint+`", "reason": "test"}`)
	}

	path := filepath.Join(t.TempDir(), "denylist.json")

	contents := `{"distrusted_roots": [` + strings.Join(entries, ",") + `]}`

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write test denylist: %v", err)
	}

	return path
}

func packageJSON(t *testing.T, certs ...string) string {
	t.Helper()

	out, err := json.Marshal(fspkg.Package{
		Name:    "cert-manager-debian-test",
		Version: "20250419.0",
		Bundle:  strings.Join(certs, "\n") + "\n",
	})
	if err != nil {
		t.Fatalf("failed to marshal test package: %v", err)
	}

	return string(out)
}

func TestRun(t *testing.T) {
	clean := packageJSON(t, dummy.TestCertificate1, dummy.TestCertificate2)
	contaminated := packageJSON(t, dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3)

	denylistPath := writeDenylist(t, fingerprintOf(t, dummy.TestCertificate3))

	tests := map[string]struct {
		args     []string
		input    string
		expError bool
	}{
		"a valid package with no denylist flag passes": {
			args:  nil,
			input: clean,
		},
		"an invalid package with no denylist flag fails": {
			args:     nil,
			input:    `{"name": "", "version": "", "bundle": ""}`,
			expError: true,
		},
		"a package containing no denylisted roots passes": {
			args:  []string{"--denylist", denylistPath},
			input: clean,
		},
		"a package containing a denylisted root fails": {
			args:     []string{"--denylist", denylistPath},
			input:    contaminated,
			expError: true,
		},
		"a package containing a denylisted root passes without the denylist flag": {
			args:  nil,
			input: contaminated,
		},
		"a missing denylist file fails": {
			args:     []string{"--denylist", filepath.Join(t.TempDir(), "nope.json")},
			input:    clean,
			expError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer

			err := run(test.args, strings.NewReader(test.input), &stderr)
			if (err != nil) != test.expError {
				t.Fatalf("expError=%v, got err=%v", test.expError, err)
			}
		})
	}
}

func TestRunNamesTheDenylistedRoot(t *testing.T) {
	fingerprint := fingerprintOf(t, dummy.TestCertificate3)

	var stderr bytes.Buffer

	err := run(
		[]string{"--denylist", writeDenylist(t, fingerprint)},
		strings.NewReader(packageJSON(t, dummy.TestCertificate1, dummy.TestCertificate3)),
		&stderr,
	)
	if err == nil {
		t.Fatal("expected an error, got none")
	}

	if !strings.Contains(err.Error(), fingerprint) {
		t.Errorf("expected the error to name the offending fingerprint %s, got: %v", fingerprint, err)
	}
}
