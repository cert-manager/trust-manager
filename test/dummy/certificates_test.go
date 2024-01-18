/*
Copyright 2023 The cert-manager Authors.

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

package dummy

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"testing"
	"time"
)

func Test_DummySubjectEquality(t *testing.T) {
	// TestCertificate1 and TestCertificate2 should have the same Subjects as each other
	// since this property will allow us to write tests ensuring that different certs with
	// matching subjects are handled as separate certs.

	// Since both should be self-signed, they should also have Subject == Issuer

	// The assertions below aren't useful if the certs are identical, so other tests are required
	// to ensure that they're not; these checks are implemented in Test_DummyCertificateSanity

	cert1Block, _ := pem.Decode([]byte(TestCertificate1))
	if cert1Block == nil {
		t.Fatalf("couldn't parse a PEM block for TestCertificate1")
	}

	cert2Block, _ := pem.Decode([]byte(TestCertificate2))
	if cert1Block == nil {
		t.Fatalf("couldn't parse a PEM block for TestCertificate2")
	}

	cert1, err := x509.ParseCertificate(cert1Block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse TestCertificate1: %s", err)
	}

	cert2, err := x509.ParseCertificate(cert2Block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse TestCertificate2: %s", err)
	}

	if cert1.Subject.String() != cert2.Subject.String() {
		t.Fatalf("TestCertificate1 doesn't have the same Subject as TestCertificate2; some tests rely on this property")
	}

	err = cert1.CheckSignatureFrom(cert1)
	if err != nil {
		t.Errorf("TestCertificate1 is not self signed; this is an expected property")
	}

	err = cert2.CheckSignatureFrom(cert2)
	if err != nil {
		t.Errorf("TestCertificate2 is not self signed; this is an expected property")
	}
}

func Test_DummyCertificateSanity(t *testing.T) {
	allDummyCerts := map[string]string{
		"TestCertificate1": TestCertificate1,
		"TestCertificate2": TestCertificate2,
		"TestCertificate3": TestCertificate3,
		"TestCertificate4": TestCertificate4,
		"TestCertificate5": TestCertificate5,
	}

	equalityMap := make(map[string]struct{})

	for name, cert := range allDummyCerts {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			t.Errorf("couldn't parse a PEM block from %q", name)
			continue
		}

		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("Dummy certificate %q couldn't be parsed: %s", name, err)
			continue
		}

		pemHash := sha256.Sum256([]byte(cert))
		hexHash := hex.EncodeToString(pemHash[:])

		_, found := equalityMap[hexHash]
		if found {
			t.Errorf("at least one other dummy TestCertificate entry was identical to %q; all should be unique", name)
		}

		equalityMap[hexHash] = struct{}{}
	}
}

func Test_DummyCertificateExpiryAtInstant(t *testing.T) {
	instant := DummyInstant()

	tests := []struct {
		certName        string
		certPEM         string
		shouldBeExpired bool
	}{
		{
			certName:        "TestCertificate1",
			certPEM:         TestCertificate1,
			shouldBeExpired: false,
		},
		{
			certName:        "TestCertificate2",
			certPEM:         TestCertificate2,
			shouldBeExpired: false,
		},
		{
			certName:        "TestCertificate3",
			certPEM:         TestCertificate3,
			shouldBeExpired: false,
		},
		{
			certName:        "TestCertificate4",
			certPEM:         TestCertificate4,
			shouldBeExpired: false,
		},
		{
			certName:        "TestCertificate5",
			certPEM:         TestCertificate5,
			shouldBeExpired: false,
		},
		{
			certName:        "TestExpiredCertificate",
			certPEM:         TestExpiredCertificate,
			shouldBeExpired: true,
		},
	}

	for _, test := range tests {
		testCheck := "is not"
		if test.shouldBeExpired {
			testCheck = "is"
		}

		t.Run(fmt.Sprintf("checking %s %s expired at DummyInstant", test.certName, testCheck), func(t *testing.T) {
			block, _ := pem.Decode([]byte(test.certPEM))
			if block == nil {
				t.Errorf("couldn't parse a PEM block for %s", test.certName)
				return
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Errorf("failed to parse %s: %s", test.certName, err)
				return
			}

			isExpired := cert.NotAfter.Before(instant)

			if test.shouldBeExpired != isExpired {
				t.Errorf("%s: shouldBeExpired=%v, isExpired=%v (at instant %s)", test.certName, test.shouldBeExpired, isExpired, instant.Format(time.RFC3339))
				return
			}
		})
	}
}
