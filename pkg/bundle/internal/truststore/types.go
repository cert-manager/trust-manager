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
	"crypto/sha256"
	"encoding/hex"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"
)

type Encoder interface {
	Encode(trustBundle *util.CertPool) ([]byte, error)
}

func NewJKSEncoder(password string) Encoder {
	return NewPKCS12Encoder(password, v1alpha1.LegacyRC2PKCS12Profile)
}

func NewPKCS12Encoder(password string, profile v1alpha1.PKCS12Profile) Encoder {
	return &pkcs12Encoder{password: password, profile: profile}
}

type pkcs12Encoder struct {
	password string
	profile  v1alpha1.PKCS12Profile
}

func (e pkcs12Encoder) Encode(trustBundle *util.CertPool) ([]byte, error) {
	var entries []pkcs12.TrustStoreEntry
	for _, c := range trustBundle.Certificates() {
		entries = append(entries, pkcs12.TrustStoreEntry{
			Cert:         c,
			FriendlyName: certAlias(c.Raw, c.Subject.String()),
		})
	}

	var encoder *pkcs12.Encoder
	switch e.profile {
	case v1alpha1.LegacyRC2PKCS12Profile:
		encoder = pkcs12.LegacyRC2
	case v1alpha1.LegacyDESPKCS12Profile:
		encoder = pkcs12.LegacyDES
	case v1alpha1.Modern2023PKCS12Profile:
		encoder = pkcs12.Modern2023
	default: // Default when PKCS12 Profile is unpopulated
		encoder = pkcs12.LegacyRC2
	}

	if e.password == "" {
		encoder = pkcs12.Passwordless
	}

	return encoder.EncodeTrustStoreEntries(entries, e.password)
}

// certAlias creates a JKS-safe alias for the given DER-encoded certificate, such that
// any two certificates will have a different aliases unless they're identical in every way.
// This unique alias fixes an issue where we used the Issuer field as an alias, leading to
// different certs being treated as identical.
// The friendlyName is included in the alias as a UX feature when examining JKS files using a
// tool like `keytool`.
func certAlias(derData []byte, friendlyName string) string {
	certHashBytes := sha256.Sum256(derData)
	certHash := hex.EncodeToString(certHashBytes[:])

	// Since certHash is the part which actually distinguishes between two
	// certificates, put it first so that it won't be truncated if a cert
	// with a really long subject is added. Not sure what the upper limit
	// for length actually is, but it shouldn't matter here.

	return certHash[:8] + "|" + friendlyName
}
