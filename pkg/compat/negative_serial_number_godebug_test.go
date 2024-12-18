//go:build testnegativeserialon

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
//go:debug x509negativeserial=1

package compat

// This file is built only with the testnegativeserialon tag so that we
// can use go:debug.
// If we didn't have the build tag, we'd get an error since we'd have two
// tests duplicating the x509negativeserial go:debug constraint

import (
	"crypto/x509"
	"testing"
)

func TestNegativeSerialNumberCASanityGoDebugOn(t *testing.T) {
	// Check that the special-cased CA doesn't produce any errors if
	// x509negativeserial is set to `1`. This lets us be confident that
	// ParseCertificate is only special casing the negative serial number err
	der := negativeSerialNumberCADER(t)

	// First, check that the stdlib ParseCertificate function works as expected
	x509Cert, x509Err := x509.ParseCertificate(der)
	if x509Err != nil {
		// use Errorf rather than Fatalf so we can compare the errors between
		// our implementation and x509.ParseCertificate
		t.Errorf("expected negativeSerialNumberCA to produce no error with x509negativeserial=1 using x509.ParseCertificate but got: %s", x509Err)
	}

	// Next, check that our wrapper works as expected
	cert, err := ParseCertificate(der)
	if err != nil {
		t.Errorf("expected negativeSerialNumberCA to produce no error with x509negativeserial=1 using compat.ParseCertificate but got: %s", err)
	}

	if x509Cert == nil && cert == nil {
		return
	}

	if !x509Cert.Equal(cert) {
		t.Errorf("expected certs from x509.ParseCertificate and compat.ParseCertificate to be equal but they differ")
	}
}
