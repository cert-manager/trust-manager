//go:build !testnegativeserialon

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

// 2024-12-17: The gocheckcompilerdirectives linter hasn't been updated for
// some time, and doesn't know about the go:debug directive and so must be
// disabled in this file.
// The nolint is here so that we still lint the go:build at the top of the file.
//nolint:gocheckcompilerdirectives
//go:debug x509negativeserial=0

package compat

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestNegativeSerialNumberCASanity(t *testing.T) {
	// Check that parsing the special cased cert with x509negativeserial=0
	// actually does result in an error describing the negative serial number
	// This also checks that the our value for the err (negativeSerialNumberErr)
	// is correct, since that error value isn't exported from the x509 package
	der := negativeSerialNumberCADER(t)

	x509Cert, x509Err := x509.ParseCertificate(der)
	if x509Err == nil {
		// has to be fatal since we inspect the error later
		t.Fatalf("expected negativeSerialNumberCA to produce an error with x509negativeserial=0 and x509.ParseCertificate")
	}

	if x509Cert != nil {
		t.Errorf("expected negativeSerialNumberCA to produce a nil cert with x509negativeserial=0 and x509.ParseCertificate")
	}

	if !strings.HasSuffix(x509Err.Error(), negativeSerialNumberErr) {
		t.Fatalf("expected error from parsing special case cert to end with %s with x509negativeserial=0; got %s", negativeSerialNumberErr, x509Err.Error())
	}
}

func TestParseCertificateSpecialCase(t *testing.T) {
	// Check that our special casing logic works as expected when we use ParseCertificate
	der := negativeSerialNumberCADER(t)

	// get the error from the function we wrap, so we can compare errors later
	_, x509Err := x509.ParseCertificate(der)
	if x509Err == nil {
		// has to be fatal since we use the error later
		t.Fatalf("expected negativeSerialNumberCA to produce an error with x509negativeserial=0 and x509.ParseCertificate")
	}

	// now call _our_ compat.ParseCertificate function to test the output
	cert, err := ParseCertificate(der)
	if err == nil {
		// has to be fatal since the below checks aren't valid if this doesn't error
		t.Fatalf("expected negativeSerialNumberCA to produce an error with x509negativeserial=0 and compat.ParseCertificate")
	}

	if cert != nil {
		t.Errorf("expected negativeSerialNumberCA to produce a nil cert with x509negativeserial=0 and compat.ParseCertificate")
	}

	if !IsSkipError(err) {
		t.Errorf("expected IsSkipError to be true for the error from compat.ParseCertificate with negativeSerialNumberCA and x509negativeserial=0")
	}

	var compatErr Error
	if !errors.As(err, &compatErr) {
		t.Errorf("expected error from compat.ParseCertificate with negativeSerialNumberCA and x509negativeserial=0 to be a compat.Error")
		return
	}

	if compatErr.Unwrap().Error() != x509Err.Error() {
		t.Errorf("expected underlying compat error to match error from x509.ParseCertificate but got:\ncompatError: %s\nx509 Error: %s", compatErr.Unwrap().Error(), x509Err.Error())
	}

	if compatErr.Error() == x509Err.Error() {
		t.Errorf("expected compat.Error error to be different to error from x509.ParseCertificate")
	}
}

func TestNegativeSerialNumberCAFingerprint(t *testing.T) {
	// ensure that the fingerprint we have matches the CA we test against
	der := negativeSerialNumberCADER(t)

	fingerprintBytes := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])

	if fingerprint != negativeSerialNumberCAFingerprint {
		t.Fatalf("expected fingerprint in negativeSerialNumberCAFingerprint to be %s but got: %s", fingerprint, negativeSerialNumberCAFingerprint)
	}
}
