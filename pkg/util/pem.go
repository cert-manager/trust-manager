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
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ValidateAndSanitizePEMBundle strictly validates a given input PEM bundle to confirm it contains
// only valid CERTIFICATE PEM blocks. If successful, returns the validated PEM blocks with any
// comments or extra data stripped.

// This validation is broadly similar to the standard library funtion
// crypto/x509.CertPool.AppendCertsFromPEM - that is, we decode each PEM block at a time and parse
// it as a certificate.

// The difference here is that we want to ensure that the bundle _only_ contains certificates, and
// not just skip over things which aren't certificates.

// If, for example, someone accidentally used a combined cert + private key as an input to a trust
// bundle, we wouldn't want to then distribute the private key in the target.

// In addition, the standard library AppendCertsFromPEM also silently skips PEM blocks with
// non-empty Headers. We error on such PEM blocks, for the same reason as above; headers could
// contain (accidental) private information. They're also non-standard according to
// https://www.rfc-editor.org/rfc/rfc7468

type ValidateAndSanitizeOptions struct {
	FilterExpired bool // If true, expired certificates will be filtered out
}

// ValidateAndSanitizePEMBundle keeps the original function signature for backward compatibility
func ValidateAndSanitizePEMBundle(data []byte) ([]byte, error) {
	opts := ValidateAndSanitizeOptions{
		FilterExpired: false,
	}
	return ValidateAndSanitizePEMBundleWithOptions(data, opts)
}

// ValidateAndSplitPEMBundle keeps the original function signature for backward compatibility
func ValidateAndSplitPEMBundle(data []byte) ([][]byte, error) {
	opts := ValidateAndSanitizeOptions{
		FilterExpired: false,
	}
	return ValidateAndSplitPEMBundleWithOptions(data, opts)
}

// See also https://github.com/golang/go/blob/5d5ed57b134b7a02259ff070864f753c9e601a18/src/crypto/x509/cert_pool.go#L201-L239
// An option to enable filtering of expired certificates is available.
func ValidateAndSanitizePEMBundleWithOptions(data []byte, opts ValidateAndSanitizeOptions) ([]byte, error) {
	certificates, err := ValidateAndSplitPEMBundleWithOptions(data, opts)
	if err != nil {
		return nil, err
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("bundle contains no PEM certificates")
	}

	return bytes.TrimSpace(bytes.Join(certificates, nil)), nil
}

// ValidateAndSplitPEMBundleWithOptions takes a PEM bundle as input, validates it and
// returns the list of certificates as a slice, allowing them to be iterated over.
// This process involves performs deduplication of certificates to ensure
// no duplicated certificates in the bundle.
// For details of the validation performed, see the comment for ValidateAndSanitizePEMBundle
// An option to enable filtering of expired certificates is available.
func ValidateAndSplitPEMBundleWithOptions(data []byte, opts ValidateAndSanitizeOptions) ([][]byte, error) {
	var certPool *certPool = newCertPool(opts.FilterExpired) // put PEM encoded certificate into a pool

	err := certPool.appendCertFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("invalid PEM block in bundle; invalid PEM certificate: %w", err)
	}

	return certPool.getCertsPEM(), nil
}

// DecodeX509CertificateChainBytes will decode a PEM encoded x509 Certificate chain.
func DecodeX509CertificateChainBytes(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	var block *pem.Block

	for {
		// decode the tls certificate pem
		block, certBytes = pem.Decode(certBytes)
		if block == nil {
			break
		}

		// parse the tls certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing TLS certificate: %s", err.Error())
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("error decoding certificate PEM block")
	}

	return certs, nil
}
