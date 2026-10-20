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
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cert-manager/trust-manager/pkg/compat"
	"github.com/cert-manager/trust-manager/pkg/denylist"
	"github.com/cert-manager/trust-manager/test/dummy"
)

// fingerprintOf returns the uppercase hex SHA-256 fingerprint of the first
// certificate in the given PEM, in the form used in the denylist file.
func fingerprintOf(t *testing.T, certPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("invalid test data: failed to decode PEM")
	}

	return denylist.FingerprintCert(block.Bytes).String()
}

// writeDenylist writes a denylist containing the given fingerprints to a
// temporary file and returns its path.
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

// bundle joins PEM certificates the way Debian's ca-certificates.crt does.
func bundle(certs ...string) string {
	return strings.Join(certs, "\n") + "\n"
}

// subjects returns the subject of each certificate in a PEM bundle, in order.
func subjects(t *testing.T, bundlePEM []byte) []string {
	t.Helper()

	var out []string

	rest := bundlePEM

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}

		cert, err := compat.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate from output: %v", err)
		}

		out = append(out, cert.Subject.String())
	}
}

func TestFilterRemovesDenylistedCertificate(t *testing.T) {
	input := bundle(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3)

	path := writeDenylist(t, fingerprintOf(t, dummy.TestCertificate2))

	var stdout, stderr bytes.Buffer

	if err := run([]string{"--denylist", path}, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := subjects(t, stdout.Bytes())

	want := []string{
		subjects(t, []byte(dummy.TestCertificate1))[0],
		subjects(t, []byte(dummy.TestCertificate3))[0],
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d certificates in the output, got %d", len(want), len(got))
	}

	// Ordering of retained certificates must follow the input.
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("certificate %d: expected %q, got %q", i, want[i], got[i])
		}
	}

	if !strings.Contains(stderr.String(), "removed 1 of 3 certificates") {
		t.Errorf("expected a removal summary on stderr, got:\n%s", stderr.String())
	}

	// The report must name the subject parsed from the removed certificate.
	removedSubject := subjects(t, []byte(dummy.TestCertificate2))[0]
	if !strings.Contains(stderr.String(), removedSubject) {
		t.Errorf("expected stderr to name the removed certificate %q, got:\n%s", removedSubject, stderr.String())
	}
}

// unparseableCertificatePEM is a well-formed CERTIFICATE block whose body
// isn't valid DER, standing in for a root we can fingerprint but not parse.
func unparseableCertificatePEM() string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not a certificate"),
	}))
}

func TestFilterRemovesDenylistedCertificateWhichCannotBeParsed(t *testing.T) {
	unparseable := unparseableCertificatePEM()

	input := bundle(dummy.TestCertificate1, unparseable)

	// Matching is on the raw DER, so denying a root we can't parse must still
	// remove it rather than abort the whole filter.
	path := writeDenylist(t, fingerprintOf(t, unparseable))

	var stdout, stderr bytes.Buffer

	if err := run([]string{"--denylist", path}, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatalf("expected an unparseable but denylisted certificate to be removed, got: %v", err)
	}

	got := subjects(t, stdout.Bytes())

	want := subjects(t, []byte(dummy.TestCertificate1))
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("expected only %v to survive, got %v", want, got)
	}

	if !strings.Contains(stderr.String(), "<unparseable certificate>") {
		t.Errorf("expected stderr to report the removed certificate as unparseable, got:\n%s", stderr.String())
	}

	if !strings.Contains(stderr.String(), "removed 1 of 2 certificates") {
		t.Errorf("expected 'removed 1 of 2 certificates' on stderr, got:\n%s", stderr.String())
	}
}

func TestFilterEmptyDenylistMatchIsNotAnError(t *testing.T) {
	input := bundle(dummy.TestCertificate1, dummy.TestCertificate2)

	// A denylist which is valid but matches nothing: the expected steady state
	// once Debian removes a listed root for us.
	path := writeDenylist(t, strings.Repeat("ab", 32))

	var stdout, stderr bytes.Buffer

	if err := run([]string{"--denylist", path}, strings.NewReader(input), &stdout, &stderr); err != nil {
		t.Fatalf("expected a denylist matching nothing to succeed, got: %v", err)
	}

	if got := len(subjects(t, stdout.Bytes())); got != 2 {
		t.Errorf("expected both certificates to survive, got %d", got)
	}

	if !strings.Contains(stderr.String(), "removed 0 of 2 certificates") {
		t.Errorf("expected 'removed 0 of 2 certificates' on stderr, got:\n%s", stderr.String())
	}
}

func TestFilterOutputIsStable(t *testing.T) {
	input := bundle(dummy.TestCertificate1, dummy.TestCertificate2)

	path := writeDenylist(t, strings.Repeat("ab", 32))

	var first, second, stderr bytes.Buffer

	if err := run([]string{"--denylist", path}, strings.NewReader(input), &first, &stderr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-filtering the filter's own output must be a fixed point: the encoding
	// is canonical, so a second pass changes nothing.
	if err := run([]string{"--denylist", path}, bytes.NewReader(first.Bytes()), &second, &stderr); err != nil {
		t.Fatalf("unexpected error on second pass: %v", err)
	}

	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Error("expected filtering to be idempotent, but the second pass produced different bytes")
	}

	if !bytes.HasPrefix(first.Bytes(), []byte("-----BEGIN CERTIFICATE-----\n")) {
		t.Error("expected the output to start with a canonical PEM header")
	}
}

func TestFilterErrors(t *testing.T) {
	validBundle := bundle(dummy.TestCertificate1, dummy.TestCertificate2)

	tests := map[string]struct {
		args  []string
		input string
	}{
		"no denylist flag": {
			args:  nil,
			input: validBundle,
		},
		"missing denylist file": {
			args:  []string{"--denylist", filepath.Join(t.TempDir(), "nope.json")},
			input: validBundle,
		},
		"input is not a PEM bundle": {
			args:  []string{"--denylist", writeDenylist(t, strings.Repeat("ab", 32))},
			input: "this is not a certificate",
		},
		// A combined cert + key must be rejected rather than silently
		// stripped, so that we can't accidentally ship key material.
		"input contains a non-certificate PEM block": {
			args:  []string{"--denylist", writeDenylist(t, strings.Repeat("ab", 32))},
			input: validBundle + "-----BEGIN RSA PRIVATE KEY-----\nbm90IGEga2V5\n-----END RSA PRIVATE KEY-----\n",
		},
		"input is empty": {
			args:  []string{"--denylist", writeDenylist(t, strings.Repeat("ab", 32))},
			input: "",
		},
		// pem.Decode skips a block with a corrupt body and returns the next
		// one which decodes. Dropping the malformed block would silently
		// shrink the bundle, and final-package validation can't detect a loss
		// it never knew about, so this has to fail the build.
		"malformed PEM block before a valid certificate": {
			args: []string{"--denylist", writeDenylist(t, strings.Repeat("ab", 32))},
			input: "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n" +
				validBundle,
		},
		// A certificate we're keeping is one we're about to ship, so being
		// unable to parse it is fatal even though an identical certificate on
		// the denylist would just be removed.
		"retained certificate cannot be parsed": {
			args:  []string{"--denylist", writeDenylist(t, strings.Repeat("ab", 32))},
			input: bundle(dummy.TestCertificate1, unparseableCertificatePEM()),
		},
		"every certificate is removed": {
			args: []string{"--denylist", writeDenylist(t,
				fingerprintOf(t, dummy.TestCertificate1),
				fingerprintOf(t, dummy.TestCertificate2),
			)},
			input: validBundle,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			err := run(test.args, strings.NewReader(test.input), &stdout, &stderr)
			if err == nil {
				t.Fatal("expected an error, got none")
			}

			if stdout.Len() != 0 {
				t.Errorf("expected nothing to be written to stdout on failure, got %d bytes", stdout.Len())
			}
		})
	}
}

func TestFilterMalformedDenylistFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denylist.json")

	contents := `{"distrusted_roots": [{"sha256": "not-a-fingerprint", "reason": "test"}]}`

	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("failed to write test denylist: %v", err)
	}

	var stdout, stderr bytes.Buffer

	err := run([]string{"--denylist", path}, strings.NewReader(bundle(dummy.TestCertificate1)), &stdout, &stderr)
	if err == nil {
		t.Fatal("expected a malformed fingerprint to be rejected, got no error")
	}

	if !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("expected the error to mention the fingerprint, got: %v", err)
	}
}
