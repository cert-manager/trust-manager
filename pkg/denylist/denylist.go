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

// Package denylist reads the list of distrusted root certificates which are
// filtered out of the trust packages we build. It's used at build time by
// cmd/filter-trust-package (to remove them) and by cmd/validate-trust-package
// (to assert they're absent from the bundle we're about to ship).
package denylist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Fingerprint is the SHA-256 digest of a certificate's DER encoding.
type Fingerprint [sha256.Size]byte

// String renders a fingerprint as uppercase hex, matching the form used in the
// denylist file and in the output of `openssl x509 -fingerprint -sha256`.
func (f Fingerprint) String() string {
	return strings.ToUpper(hex.EncodeToString(f[:]))
}

// FingerprintCert returns the fingerprint of a DER-encoded certificate. The
// input is the raw DER rather than a parsed *x509.Certificate so that a
// certificate which fails to parse can still be matched.
func FingerprintCert(der []byte) Fingerprint {
	return sha256.Sum256(der)
}

// Entry is a single distrusted root.
type Entry struct {
	// SHA256 is the SHA-256 fingerprint of the root's DER encoding. It's
	// compared case-insensitively with separators stripped, so it can be
	// pasted in whatever form the source gives it.
	SHA256 string `json:"sha256"`

	// Reason documents why the root is distrusted. The denylist deliberately
	// carries no certificate name or operator - both are redundant with what
	// the certificate itself carries and a copy here can drift - so Reason
	// carries the whole documentary burden and is mandatory.
	Reason string `json:"reason"`
}

type denylistFile struct {
	DistrustedRoots []Entry `json:"distrusted_roots"`
}

// Denylist is a set of distrusted roots indexed by fingerprint.
type Denylist struct {
	entries map[Fingerprint]Entry
}

// LoadFile reads a denylist from the given path.
func LoadFile(path string) (*Denylist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open denylist %q: %w", path, err)
	}

	defer f.Close()

	dl, err := Load(f)
	if err != nil {
		return nil, fmt.Errorf("failed to load denylist %q: %w", path, err)
	}

	return dl, nil
}

// Load reads a denylist from the given reader.
//
// An empty denylist is rejected: every caller of this package only has reason
// to read a denylist in order to act on it, so an empty one means the file has
// been renamed, reformatted or emptied by mistake, and silently filtering
// nothing is the exact failure we're trying to avoid. Note that this is not the
// same as a denylist which matches no certificates, which is expected - see
// cmd/filter-trust-package.
func Load(reader io.Reader) (*Denylist, error) {
	var parsed denylistFile

	decoder := json.NewDecoder(reader)
	// Be strict: a typo'd or renamed key would otherwise produce a denylist
	// which silently matches nothing.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("failed to parse denylist JSON: %w", err)
	}

	if len(parsed.DistrustedRoots) == 0 {
		return nil, fmt.Errorf("denylist contains no entries under 'distrusted_roots'")
	}

	entries := make(map[Fingerprint]Entry, len(parsed.DistrustedRoots))

	for i, entry := range parsed.DistrustedRoots {
		fingerprint, err := ParseFingerprint(entry.SHA256)
		if err != nil {
			return nil, fmt.Errorf("denylist entry %d: %w", i, err)
		}

		if strings.TrimSpace(entry.Reason) == "" {
			return nil, fmt.Errorf("denylist entry %d (%s): 'reason' must not be empty", i, fingerprint)
		}

		if _, duplicate := entries[fingerprint]; duplicate {
			return nil, fmt.Errorf("denylist entry %d: duplicate fingerprint %s", i, fingerprint)
		}

		entries[fingerprint] = entry
	}

	return &Denylist{entries: entries}, nil
}

// ParseFingerprint normalises a SHA-256 fingerprint written in any of the
// common forms - uppercase or lowercase, with or without colon, space or
// hyphen separators - and rejects anything which isn't 32 hex-encoded bytes.
// Rejecting rather than normalising to something unmatchable matters: a
// malformed fingerprint would otherwise be indistinguishable from a root which
// simply isn't present.
func ParseFingerprint(s string) (Fingerprint, error) {
	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '-', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)

	if len(cleaned) != hex.EncodedLen(sha256.Size) {
		return Fingerprint{}, fmt.Errorf("invalid sha256 fingerprint %q: expected %d hex characters, got %d", s, hex.EncodedLen(sha256.Size), len(cleaned))
	}

	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return Fingerprint{}, fmt.Errorf("invalid sha256 fingerprint %q: %w", s, err)
	}

	return Fingerprint(raw), nil
}

// Lookup returns the entry matching the given fingerprint, if any.
func (d *Denylist) Lookup(fingerprint Fingerprint) (Entry, bool) {
	entry, found := d.entries[fingerprint]
	return entry, found
}

// Len returns the number of entries in the denylist.
func (d *Denylist) Len() int {
	return len(d.entries)
}
