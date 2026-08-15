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

package util

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"hegel.dev/go/hegel"
)

// testCert is a self-signed certificate generated once per test run, in the
// canonical PEM encoding that CertPool.PEM emits.
type testCert struct {
	cert    *x509.Certificate
	pem     string
	expired bool
	isCA    bool
}

// newTestCerts generates a mix of CA/non-CA and valid/expired self-signed
// certificates. Ed25519 keeps generation fast.
func newTestCerts(t *testing.T) []testCert {
	t.Helper()

	var certs []testCert
	for i, spec := range []struct {
		cn      string
		expired bool
		isCA    bool
	}{
		{"ca-a", false, true},
		{"ca-b", false, true},
		// Same subject as ca-b, different key: distinct certs which collide
		// on every name-based property.
		{"ca-b", false, true},
		{"ca-expired", true, true},
		{"leaf", false, false},
		{"leaf-expired", true, false},
	} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		notAfter := time.Now().Add(24 * time.Hour)
		if spec.expired {
			notAfter = time.Now().Add(-24 * time.Hour)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: spec.cn, Organization: []string{"trust-manager-hegel"}},
			NotBefore:             time.Now().Add(-48 * time.Hour),
			NotAfter:              notAfter,
			IsCA:                  spec.isCA,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, testCert{
			cert:    cert,
			pem:     strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))),
			expired: spec.expired,
			isCA:    spec.isCA,
		})
	}
	return certs
}

// drawBundle interleaves drawn certificates (possibly duplicated) with
// non-PEM junk text, as found in real-world bundles such as
// /etc/ssl/certs/ca-certificates.crt with comments.
func drawBundle(ht *hegel.T, certs []testCert) (string, []testCert) {
	junk := []string{"", "some random commentary", "\xff\xfe", "-----", "abc123", "\t "}

	var parts []string
	var drawn []testCert
	for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(certs)-1)).MaxSize(6)) {
		if hegel.Draw(ht, hegel.Booleans()) {
			parts = append(parts, hegel.Draw(ht, hegel.SampledFrom(junk)))
		}
		parts = append(parts, certs[i].pem)
		drawn = append(drawn, certs[i])
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		parts = append(parts, hegel.Draw(ht, hegel.SampledFrom(junk)))
	}
	return strings.Join(parts, "\n"), drawn
}

// TestAddCertsFromPEMProperties: for any bundle of valid certificates
// interleaved with junk text, AddCertsFromPEM succeeds and the pool holds
// exactly the distinct certificates that pass the configured filters:
//
//   - deduplication is by SHA256 of the DER bytes
//   - WithFilteredExpiredCerts drops exactly the expired certificates,
//     WithFilteredNonCaCerts exactly the non-CAs
//   - Certificates() returns them sorted by that hash
//   - PEM() is a fixed point: re-adding its output to a fresh pool yields
//     byte-identical PEM, and the output is valid UTF-8 with no junk
//   - PEMSplit() is PEM() split per certificate
//
// Note the pool accepts a bundle with no certificates at all: the doc
// comment on AddCertsFromPEM claims an error in that case, but no such error
// is returned (the pre-existing table test pinned the same behavior).
func TestAddCertsFromPEMProperties(t *testing.T) {
	certs := newTestCerts(t)

	hegel.Test(t, func(ht *hegel.T) {
		bundle, drawn := drawBundle(ht, certs)
		filterExpired := hegel.Draw(ht, hegel.Booleans())
		filterNonCA := hegel.Draw(ht, hegel.Booleans())

		pool := NewCertPool(WithFilteredExpiredCerts(filterExpired), WithFilteredNonCaCerts(filterNonCA))
		if err := pool.AddCertsFromPEM([]byte(bundle)); err != nil {
			ht.Fatalf("valid bundle rejected: %v", err)
		}

		want := map[[32]byte]testCert{}
		for _, c := range drawn {
			if (filterExpired && c.expired) || (filterNonCA && !c.isCA) {
				continue
			}
			want[sha256.Sum256(c.cert.Raw)] = c
		}
		if pool.Size() != len(want) {
			ht.Fatalf("pool size = %d, want %d", pool.Size(), len(want))
		}

		got := pool.Certificates()
		hashes := make([][32]byte, 0, len(got))
		for _, c := range got {
			hash := sha256.Sum256(c.Raw)
			if _, ok := want[hash]; !ok {
				ht.Fatalf("pool contains unexpected certificate %q", c.Subject)
			}
			hashes = append(hashes, hash)
		}
		if !slices.IsSortedFunc(hashes, func(a, b [32]byte) int { return slices.Compare(a[:], b[:]) }) {
			ht.Fatalf("Certificates() not sorted by SHA256")
		}

		pemOut := pool.PEM()
		if !utf8.ValidString(pemOut) {
			ht.Fatalf("PEM() output is not valid UTF-8")
		}
		wantPEMs := make([]string, 0, len(got))
		for _, c := range got {
			wantPEMs = append(wantPEMs, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))))
		}
		if join := strings.Join(wantPEMs, "\n"); pemOut != join {
			ht.Fatalf("PEM() = %q, want %q", pemOut, join)
		}
		if split := pool.PEMSplit(); !slices.Equal(split, wantPEMs) && len(split)+len(wantPEMs) > 0 {
			ht.Fatalf("PEMSplit() = %q, want %q", split, wantPEMs)
		}

		// Fixed point: the sanitized output must survive a round trip intact.
		rePool := NewCertPool()
		if err := rePool.AddCertsFromPEM([]byte(pemOut)); err != nil {
			ht.Fatalf("PEM() output rejected on re-add: %v", err)
		}
		if rePool.PEM() != pemOut {
			ht.Fatalf("PEM() not a fixed point:\nfirst= %q\nsecond=%q", pemOut, rePool.PEM())
		}
	}, hegel.WithTestCases(1000))
}

// TestAddCertsFromPEMRejectsInvalidBlocks: a bundle is rejected as a whole
// if any PEM block is not a parseable, header-free CERTIFICATE block. This
// is the trust boundary that keeps private keys and other stray material out
// of distributed trust bundles.
func TestAddCertsFromPEMRejectsInvalidBlocks(t *testing.T) {
	certs := newTestCerts(t)

	hegel.Test(t, func(ht *hegel.T) {
		var poison string
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			// A non-CERTIFICATE block, e.g. an accidentally pasted private key.
			typ := hegel.Draw(ht, hegel.SampledFrom([]string{"EC PRIVATE KEY", "RSA PRIVATE KEY", "PRIVATE KEY", "X509 CRL", "TRUSTED CERTIFICATE"}))
			poison = string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: hegel.Draw(ht, hegel.Binary(0, 100))}))
		case 1:
			// A CERTIFICATE block with PEM headers, which could carry private data.
			c := certs[hegel.Draw(ht, hegel.Integers(0, len(certs)-1))]
			poison = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"My-Header": "Abc123"}, Bytes: c.cert.Raw}))
		case 2:
			// A CERTIFICATE block whose contents do not parse as a certificate.
			c := certs[hegel.Draw(ht, hegel.Integers(0, len(certs)-1))]
			truncated := c.cert.Raw[:hegel.Draw(ht, hegel.Integers(0, len(c.cert.Raw)-1))]
			poison = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: truncated}))
		}

		before, _ := drawBundle(ht, certs)
		after, _ := drawBundle(ht, certs)
		bundle := strings.Join([]string{before, poison, after}, "\n")

		pool := NewCertPool()
		if err := pool.AddCertsFromPEM([]byte(bundle)); err == nil {
			ht.Fatalf("bundle with invalid block accepted; poison: %q", poison)
		}
	}, hegel.WithTestCases(1000))
}

// TestAddCertsFromPEMArbitraryBytes: arbitrary input must never panic, a nil
// input is always an error, and whenever the input is accepted the resulting
// PEM() output must itself be a valid bundle (fixed point).
func TestAddCertsFromPEMArbitraryBytes(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		var data []byte
		if hegel.Draw(ht, hegel.Booleans()) {
			data = hegel.Draw(ht, hegel.Binary(0, 300))
		}

		pool := NewCertPool()
		err := pool.AddCertsFromPEM(data)
		if data == nil {
			if err == nil {
				ht.Fatalf("nil input accepted")
			}
			return
		}
		if err != nil {
			return
		}
		rePool := NewCertPool()
		if reErr := rePool.AddCertsFromPEM([]byte(pool.PEM())); reErr != nil {
			ht.Fatalf("accepted input %q but PEM() output rejected: %v", data, reErr)
		}
	}, hegel.WithTestCases(1000))
}
