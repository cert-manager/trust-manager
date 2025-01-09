/*
Copyright 2024 The cert-manager Authors.

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

package compat

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// IsSkipError returns true if the error means the cert should be skipped over
// rather than being a fatal error
func IsSkipError(err error) bool {
	return errors.As(err, &Error{})
}

// Error is returned when there's a certificate compatibility error which
// implies that a certificate should be skipped
type Error struct {
	Underlying error
	Message    string
}

func (e Error) Unwrap() error {
	return e.Underlying
}

func (e Error) Error() string {
	return e.Message
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data
// This is a wrapper for the x509.ParseCertificate function, handling the
// special case of a cert in a public trust bundle with a negative serial number
// which produces an error by default in Go 1.23.
// If using Go 1.22 or older, or if using Go 1.23 or newer and the GODEBUG
// value `x509negativeserial` is set to `1`, that specific cert will parse
// with no error.
// Otherwise, a special Error value will be returned so that the certificate
// can be skipped using IsSkipError
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}

	// If there was an error, check if the cert is the special case
	fingerprintBytes := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])

	if fingerprint == negativeSerialNumberCAFingerprint {
		// The cert was the special case; handle it differently
		return handleNegativeSerialNumberSpecialCase(cert, err)
	}

	// if the error is for a cert we have NOT special cased, return the
	// error as we received it (to avoid allowing negative serial numbers
	// for any other CAs, such as in private PKI)
	return cert, err
}

func handleNegativeSerialNumberSpecialCase(cert *x509.Certificate, err error) (*x509.Certificate, error) {
	// The cert was the special case; check if the error was due to a
	// negative serial number (to account for future changes to ParseCertificate
	// which could return a different error, although we do test that)
	if !strings.HasSuffix(err.Error(), negativeSerialNumberErr) {
		return cert, err
	}

	message := fmt.Sprintf("cert in bundle with CN=EC-ACC and fingerprint '%s' has negative serial number and will be skipped", negativeSerialNumberCAFingerprint)

	return nil, Error{Underlying: err, Message: message}
}
