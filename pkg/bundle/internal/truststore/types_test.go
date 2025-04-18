/*
Copyright 2021 The cert-manager Authors.

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
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func Test_Encoder_Deterministic(t *testing.T) {
	tests := map[string]struct {
		encoder             Encoder
		expNonDeterministic bool
	}{
		"JKS default password": {
			encoder:             NewJKSEncoder(v1alpha1.DefaultJKSPassword),
			expNonDeterministic: true,
		},
		"JKS custom password": {
			encoder:             NewJKSEncoder("my-password"),
			expNonDeterministic: true,
		},
		"PKCS#12 default password": {
			encoder: NewPKCS12Encoder(v1alpha1.DefaultPKCS12Password, ""),
		},
		"PKCS#12 default password, DES encryption": {
			encoder: NewPKCS12Encoder(v1alpha1.DefaultPKCS12Password, "LegacyDES"),
		},
		"PKCS#12 default password, modern encryption": {
			encoder: NewPKCS12Encoder(v1alpha1.DefaultPKCS12Password, "Modern2023"),
		},
		"PKCS#12 custom password": {
			encoder:             NewPKCS12Encoder("my-password", ""),
			expNonDeterministic: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			bundle := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3)

			certPool := util.NewCertPool()
			if err := certPool.AddCertsFromPEM([]byte(bundle)); err != nil {
				t.Fatalf("didn't expect an error but got: %s", err)
			}

			store, err := test.encoder.Encode(certPool)
			if err != nil {
				t.Fatalf("didn't expect an error but got: %s", err)
			}

			store2, err := test.encoder.Encode(certPool)
			if err != nil {
				t.Fatalf("didn't expect an error but got: %s", err)
			}

			if test.expNonDeterministic {
				assert.NotEqual(t, store, store2, "expected encoder to be non-deterministic")
			} else {
				assert.Equal(t, store, store2, "expected encoder to be deterministic")
			}
		})
	}
}

func Test_encodeJKSAliases(t *testing.T) {
	// IMPORTANT: We use TestCertificate1 and TestCertificate2 here because they're defined
	// to be self-signed and to also use the same Subject, while being different certs.
	// This test ensures that the aliases we create when adding to a JKS file is different under
	// these conditions (where the issuer / subject is identical).
	// Using different dummy certs would allow this test to pass but wouldn't actually test anything useful!
	bundle := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2)

	certPool := util.NewCertPool()
	if err := certPool.AddCertsFromPEM([]byte(bundle)); err != nil {
		t.Fatal(err)
	}

	jksFile, err := NewJKSEncoder(v1alpha1.DefaultJKSPassword).Encode(certPool)
	if err != nil {
		t.Fatalf("didn't expect an error but got: %s", err)
	}

	certs, err := pkcs12.DecodeTrustStore(jksFile, v1alpha1.DefaultJKSPassword)
	if err != nil {
		t.Fatalf("failed to parse generated JKS file: %s", err)
	}

	if len(certs) != 2 {
		t.Fatalf("expected two certs in JKS file but got %d", len(certs))
	}
}

func Test_certAlias(t *testing.T) {
	// We might not ever rely on aliases being stable, but this test seeks
	// to enforce stability for now. It'll be easy to remove.

	// If this test starts failing after TestCertificate1 is updated, it'll
	// need to be updated with the new alias for the new cert.

	block, _ := pem.Decode([]byte(dummy.TestCertificate1))
	if block == nil {
		t.Fatalf("couldn't parse a PEM block from TestCertificate1")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Dummy certificate TestCertificate1 couldn't be parsed: %s", err)
	}

	alias := certAlias(cert.Raw, cert.Subject.String())

	expectedAlias := "548b988f|CN=cmct-test-root,O=cert-manager"

	if alias != expectedAlias {
		t.Fatalf("expected alias to be %q but got %q", expectedAlias, alias)
	}
}
