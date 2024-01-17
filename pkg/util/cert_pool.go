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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CertPool is a set of certificates.
type certPool struct {
	certificatesHashes map[[32]byte]struct{}
	certificates       []*x509.Certificate
	filterExpired      bool
}

// newCertPool returns a new, empty CertPool.
func newCertPool(filterExpired bool) *certPool {
	return &certPool{
		certificatesHashes: make(map[[32]byte]struct{}),
		certificates:       make([]*x509.Certificate, 0),
		filterExpired:      filterExpired,
	}
}

// Check if the given certificate was added to certificates bundle already
func (cp *certPool) isCertificateDuplicate(certData []byte) bool {
	// calculate hash sum of the given certificate
	hash := sha256.Sum256(certData)

	// check a hash existence
	if _, ok := cp.certificatesHashes[hash]; ok {
		return ok
	}

	// put certificate hash into a set of hashes
	cp.certificatesHashes[hash] = struct{}{}

	return false
}

// Append certificate to a pool
func (cp *certPool) appendCertFromPEM(PEMdata []byte) error {
	if PEMdata == nil {
		return fmt.Errorf("certificate data can't be nil")
	}

	for {
		var block *pem.Block
		block, PEMdata = pem.Decode(PEMdata)

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

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			// the presence of an invalid cert (including things which aren't certs)
			// should cause the bundle to be rejected
			return fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
		}

		if certificate == nil {
			return fmt.Errorf("failed appending a certificate: certificate is nil")
		}

		if cp.filterExpired && time.Now().After(certificate.NotAfter) {
			continue
		}

		if !cp.isCertificateDuplicate(block.Bytes) {
			cp.certificates = append(cp.certificates, certificate)
		}
	}

	return nil
}

// Get PEM certificates from pool
func (cp *certPool) getCertsPEM() [][]byte {
	var certsData [][]byte = make([][]byte, len(cp.certificates))

	for i, cert := range cp.certificates {
		certsData[i] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	return certsData
}
