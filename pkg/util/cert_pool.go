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

package util

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"time"

	"github.com/go-logr/logr"

	"github.com/cert-manager/trust-manager/pkg/compat"
)

// CertPool is a set of certificates.
type CertPool struct {
	certificates map[[32]byte]*x509.Certificate

	filterExpired bool

	logger logr.Logger

	useCACertsOnly bool
}

type Option func(*CertPool)

func WithFilteredExpiredCerts(filterExpired bool) Option {
	return func(cp *CertPool) {
		cp.filterExpired = filterExpired
	}
}

func WithLogger(logger logr.Logger) Option {
	return func(cp *CertPool) {
		cp.logger = logger
	}
}

func WithCACertsOnly(useCACertsOnly bool) Option {
	return func(cp *CertPool) {
		cp.useCACertsOnly = useCACertsOnly
	}
}

// NewCertPool returns a new, empty CertPool.
// It will deduplicate certificates based on their SHA256 hash.
// Optionally, it can filter out expired certificates.
func NewCertPool(options ...Option) *CertPool {
	certPool := &CertPool{
		certificates: make(map[[32]byte]*x509.Certificate),

		logger: logr.Discard(),
	}

	for _, option := range options {
		option(certPool)
	}

	return certPool
}

// AddCertsFromPEM strictly validates a given input PEM bundle to confirm it contains
// only valid CERTIFICATE PEM blocks. If successful, returns the validated PEM blocks with any
// comments or extra data stripped.
//
// This validation is broadly similar to the standard library function
// crypto/x509.CertPool.AppendCertsFromPEM - that is, we decode each PEM block at a time and parse
// it as a certificate.
//
// The difference here is that we want to ensure that the bundle _only_ contains certificates, and
// not just skip over things which aren't certificates.
//
// If, for example, someone accidentally used a combined cert + private key as an input to a trust
// bundle, we wouldn't want to then distribute the private key in the target.
//
// In addition, the standard library AppendCertsFromPEM also silently skips PEM blocks with
// non-empty Headers. We error on such PEM blocks, for the same reason as above; headers could
// contain (accidental) private information. They're also non-standard according to
// https://www.rfc-editor.org/rfc/rfc7468
//
// Additionally, if the input PEM bundle contains no non-expired certificates, an error is returned.
func (cp *CertPool) AddCertsFromPEM(pemData []byte) error {
	if pemData == nil {
		return fmt.Errorf("certificate data can't be nil")
	}

	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)

		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			// only certificates are allowed in a bundle
			return fmt.Errorf("invalid PEM block in bundle: only CERTIFICATE blocks are permitted but found '%s'", block.Type)
		}

		if len(block.Headers) != 0 {
			return fmt.Errorf("invalid PEM block in bundle; blocks are not permitted to have PEM headers")
		}

		certificate, err := compat.ParseCertificate(block.Bytes)
		if err != nil {
			if compat.IsSkipError(err) {
				// there's some compatibility error; we don't want to fail
				// the whole bundle for this cert, we should just skip it
				cp.logger.Info("skipping a certificate in PEM bundle for compatibility reasons", "details", err)
				continue
			}

			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("failed appending a certificate: certificate is nil")
		}

		cp.AddCert(certificate)
	}

	return nil
}

func (cp *CertPool) AddCert(certificate *x509.Certificate) bool {
	if cp.filterExpired && time.Now().After(certificate.NotAfter) {
		cp.logger.Info("ignoring expired certificate", "certificate", certificate.Subject)
		return false
	}

	if cp.useCACertsOnly && !certificate.IsCA {
		cp.logger.Info("ignoring non-CA certificate", "certificate", certificate.Subject)
		return false
	}

	hash := sha256.Sum256(certificate.Raw)
	cp.certificates[hash] = certificate
	return true
}

// Get certificates quantity in the certificates pool
func (cp *CertPool) Size() int {
	return len(cp.certificates)
}

func (certPool *CertPool) PEM() string {
	if certPool == nil || len(certPool.certificates) == 0 {
		return ""
	}

	buffer := bytes.Buffer{}

	for _, cert := range certPool.Certificates() {
		if err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return ""
		}
	}

	return string(bytes.TrimSpace(buffer.Bytes()))
}

func (certPool *CertPool) PEMSplit() []string {
	if certPool == nil || len(certPool.certificates) == 0 {
		return nil
	}

	pems := make([]string, 0, len(certPool.certificates))
	for _, cert := range certPool.Certificates() {
		pems = append(pems, string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))))
	}

	return pems
}

// Get the list of all x509 Certificates in the certificates pool
func (certPool *CertPool) Certificates() []*x509.Certificate {
	hashes := make([][32]byte, 0, len(certPool.certificates))
	for hash := range certPool.certificates {
		hashes = append(hashes, hash)
	}

	slices.SortFunc(hashes, func(i, j [32]byte) int {
		return bytes.Compare(i[:], j[:])
	})

	orderedCertificates := make([]*x509.Certificate, 0, len(certPool.certificates))
	for _, hash := range hashes {
		orderedCertificates = append(orderedCertificates, certPool.certificates[hash])
	}

	return orderedCertificates
}
