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

package truststore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"

	"hegel.dev/go/hegel"
)

// newTestPEMs generates distinct self-signed CA certificates, two of which
// share a subject so that alias uniqueness cannot rely on names alone.
func newTestPEMs(t *testing.T) []string {
	t.Helper()

	var pems []string
	for i, cn := range []string{"ca-a", "ca-b", "ca-b", "ca-c", "ca-d"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"trust-manager-hegel"}},
			NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		pems = append(pems, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return pems
}

// TestEncodersRoundTripAndDeterminism: for any non-empty subset of
// certificates and any password/profile configuration, Encode must produce a
// store that decodes (with the same library) back to exactly the pool's
// certificates:
//
//   - JKS: one trusted-cert entry per certificate, alias certAlias(...),
//     content equal to the DER bytes, creation time NotBefore
//   - PKCS#12: DecodeTrustStore returns the pool's certificates in order
//   - encoding twice yields identical bytes for JKS and for passwordless
//     PKCS#12; PKCS#12 with a password uses random salts, so equality is not
//     asserted there
func TestEncodersRoundTripAndDeterminism(t *testing.T) {
	pems := newTestPEMs(t)
	profiles := []v1alpha1.PKCS12Profile{"", v1alpha1.LegacyRC2PKCS12Profile, v1alpha1.LegacyDESPKCS12Profile, v1alpha1.Modern2023PKCS12Profile}

	hegel.Test(t, func(ht *hegel.T) {
		pool := util.NewCertPool()
		for _, i := range hegel.Draw(ht, hegel.Lists(hegel.Integers(0, len(pems)-1)).MinSize(1).MaxSize(5)) {
			if err := pool.AddCertsFromPEM([]byte(pems[i])); err != nil {
				ht.Fatalf("failed to add cert: %v", err)
			}
		}
		certs := pool.Certificates()

		useJKS := hegel.Draw(ht, hegel.Booleans())
		var password string
		var encoder Encoder
		if useJKS {
			password = hegel.Draw(ht, hegel.SampledFrom([]string{v1alpha1.DefaultJKSPassword, "my-password", "0"}))
			encoder = NewJKSEncoder(password)
		} else {
			password = hegel.Draw(ht, hegel.SampledFrom([]string{v1alpha1.DefaultPKCS12Password, "my-password", "0"}))
			encoder = NewPKCS12Encoder(password, hegel.Draw(ht, hegel.SampledFrom(profiles)))
		}

		store, err := encoder.Encode(pool)
		if err != nil {
			ht.Fatalf("Encode failed: %v", err)
		}

		if useJKS || password == "" {
			store2, err := encoder.Encode(pool)
			if err != nil {
				ht.Fatalf("second Encode failed: %v", err)
			}
			if !bytes.Equal(store, store2) {
				ht.Fatalf("encoder not deterministic")
			}
		}

		if useJKS {
			ks := keystore.New()
			if err := ks.Load(bytes.NewReader(store), []byte(password)); err != nil {
				ht.Fatalf("failed to load generated JKS: %v", err)
			}
			if got, want := len(ks.Aliases()), len(certs); got != want {
				ht.Fatalf("JKS has %d entries, want %d", got, want)
			}
			for _, c := range certs {
				entry, err := ks.GetTrustedCertificateEntry(certAlias(c.Raw, c.Subject.String()))
				if err != nil {
					ht.Fatalf("JKS missing entry for %q: %v", c.Subject, err)
				}
				if !bytes.Equal(entry.Certificate.Content, c.Raw) {
					ht.Fatalf("JKS entry for %q has wrong certificate content", c.Subject)
				}
				if !entry.CreationTime.Equal(c.NotBefore) {
					ht.Fatalf("JKS entry for %q creation time = %v, want NotBefore %v", c.Subject, entry.CreationTime, c.NotBefore)
				}
			}
		} else {
			decoded, err := pkcs12.DecodeTrustStore(store, password)
			if err != nil {
				ht.Fatalf("failed to decode generated PKCS#12: %v", err)
			}
			if len(decoded) != len(certs) {
				ht.Fatalf("PKCS#12 has %d certs, want %d", len(decoded), len(certs))
			}
			for i, c := range certs {
				if !bytes.Equal(decoded[i].Raw, c.Raw) {
					ht.Fatalf("PKCS#12 cert %d mismatch: got %q, want %q", i, decoded[i].Subject, c.Subject)
				}
			}
		}
	}, hegel.WithTestCases(300))
}
