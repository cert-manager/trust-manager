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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cert-manager/trust-manager/test/dummy"
)

func TestAddCertsFromPEM(t *testing.T) {
	poisonComment := []byte{0xFF}
	// strippableComments is a list of things which should not be present in the output
	strippableText := [][]byte{
		[]byte(randomComment),
		poisonComment,
	}

	cases := map[string]struct {
		parts                 []string
		filterDuplicateCerts  bool
		filterExpiredCerts    bool
		expectCertCount       int
		expectExpiredCerts    bool
		expectErr             bool
		expectDuplicatesCerts bool
	}{
		"valid bundle with all types of cert and no comments succeeds": {
			parts:           []string{dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3},
			expectCertCount: 3,
			expectErr:       false,
		},
		"valid bundle with all types of cert and a random comment succeeds": {
			parts:           []string{dummy.TestCertificate1, randomComment, dummy.TestCertificate2, randomComment, dummy.TestCertificate3, randomComment},
			expectCertCount: 3,
			expectErr:       false,
		},
		"valid bundle with all types of cert and a poison comment succeeds": {
			parts:           []string{dummy.TestCertificate1, string(poisonComment), dummy.TestCertificate2, randomComment, dummy.TestCertificate3, string(poisonComment)},
			expectCertCount: 3,
			expectErr:       false,
		},
		"valid bundle with expired cert succeeds with the expired cert intact": {
			parts:              []string{dummy.TestCertificate1, dummy.TestExpiredCertificate},
			expectCertCount:    2,
			expectExpiredCerts: true,
			expectErr:          false,
		},
		"invalid bundle with a certificate with a header fails": {
			parts:     []string{dummy.TestCertificate1, dummyCertificateWithHeader, dummy.TestCertificate3},
			expectErr: true,
		},
		"invalid bundle with a certificate with invalid base64 fails": {
			parts:     []string{dummy.TestCertificate1, invalidCertificate, dummy.TestCertificate3},
			expectErr: true,
		},
		"invalid bundle containing a private key fails": {
			parts:     []string{dummy.TestCertificate1, privateKey},
			expectErr: true,
		},
		"invalid bundle with no certificates succeeds": {
			parts: []string{"abc123"},
		},
		"valid bundle with valid certs and filtered expired cert": {
			parts:              []string{dummy.TestCertificate1, dummy.TestExpiredCertificate, dummy.TestCertificate3},
			filterExpiredCerts: true,
			expectCertCount:    2,
			expectExpiredCerts: false,
			expectErr:          false,
		},
		"valid bundle with valid cert and multiple filtered expired certs": {
			parts:              []string{dummy.TestCertificate1, dummy.TestExpiredCertificate, dummy.TestExpiredCertificate},
			filterExpiredCerts: true,
			expectCertCount:    1,
			expectExpiredCerts: false,
			expectErr:          false,
		},
		"valid bundle with only a filtered expired cert": {
			parts:              []string{dummy.TestExpiredCertificate},
			filterExpiredCerts: true,
		},
		"duplicate certificate should be removed": {
			parts:                 []string{dummy.TestCertificate1, dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate1), dummy.TestCertificate2, dummy.TestCertificate2},
			filterExpiredCerts:    true,
			expectCertCount:       2,
			expectErr:             false,
			expectDuplicatesCerts: true,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			certPool := NewCertPool(WithFilteredExpiredCerts(test.filterExpiredCerts))

			inputBundle := []byte(strings.Join(test.parts, "\n"))

			err := certPool.AddCertsFromPEM(inputBundle)

			if test.expectErr != (err != nil) {
				t.Fatalf("AddCertsFromPEM: expectErr: %v | err: %v", test.expectErr, err)
			}

			if test.expectErr {
				return
			}

			if certPool.Size() != test.expectCertCount {
				t.Errorf("cert count = %d; want %d", certPool.Size(), test.expectCertCount)
			}

			for _, strippable := range strippableText {
				if bytes.Contains([]byte(certPool.PEM()), strippable) {
					// can't print the comment since it could be an invalid string
					t.Errorf("expected sanitizedBundle to not contain a comment but it did")
				}
			}

			if !utf8.ValidString(certPool.PEM()) {
				t.Error("expected sanitizedBundle to be valid UTF-8 but it wasn't")
			}

			sanitizedBundle := certPool.PEM()

			if strings.HasSuffix(sanitizedBundle, "\n") {
				t.Errorf("expected sanitizedBundle not to end with a newline")
			}

			for line := range strings.SplitSeq(sanitizedBundle, "\n") {
				// Check that each "encapsulation boundary" (-----BEGIN/END <x>-----) is on its
				// own line. ("Encapsulation boundary" is apparently the name according to rfc7468)
				if !strings.HasPrefix(line, "-----") {
					continue
				}

				if !strings.HasSuffix(line, "-----") || strings.Count(line, "-----") != 2 {
					t.Errorf("invalid encapsulation boundary on line of certificate")
				}
			}

			certs := certPool.Certificates()

			var expiredCerts []*x509.Certificate
			for _, cert := range certs {
				if cert.NotAfter.Before(dummy.DummyInstant()) {
					expiredCerts = append(expiredCerts, cert)
				}
			}

			if test.expectExpiredCerts != (len(expiredCerts) > 0) {
				t.Errorf("expectExpiredCerts=%v but got %d expired certs", test.expectExpiredCerts, len(expiredCerts))
			}

			if test.expectDuplicatesCerts {
				var hashes = make(map[[32]byte]struct{})
				for _, cert := range certs {
					hash := sha256.Sum256(cert.Raw)
					if _, ok := hashes[hash]; ok {
						t.Errorf("expectDuplicatesCerts=%v but got duplicate certs", test.expectDuplicatesCerts)
					}
				}
			}
		})
	}
}

const randomComment = `some random commentary`

const dummyCertificateWithHeader = `-----BEGIN CERTIFICATE-----
My-Header: Abc123

MIIBVDCCAQagAwIBAgIRANcos1c12CXTCm8qyZto2LswBQYDK2VwMDAxFTATBgNV
BAoTDGNlcnQtbWFuYWdlcjEXMBUGA1UEAxMOY21jdC10ZXN0LXJvb3QwHhcNMjIx
MjA1MTYyMjQyWhcNMzIxMjAyMTYyMjQyWjAwMRUwEwYDVQQKEwxjZXJ0LW1hbmFn
ZXIxFzAVBgNVBAMTDmNtY3QtdGVzdC1yb290MCowBQYDK2VwAyEAWjVDu9495KZ4
g0YFJ94jggGrt3NFXWk6Mb51pCBylSyjNTAzMBIGA1UdEwEB/wQIMAYBAf8CAQMw
HQYDVR0OBBYEFFjCqrTVVpQRdBANLzgdKx3agWxIMAUGAytlcANBAEqb5PmhXtlA
gySihG5glByO5ZajFBNBIhjOF6+yfN1Bo5XjJ7bGwVIhGoRPHCtbvsnfuQ5ySz95
CFD1BItRnQM=
-----END CERTIFICATE-----`

// invalidCertificate has random characters manually replaced with "a"s; if we'd just randomly
// deleted characters to make the base64 invalid, then pem.Decode would skip over the block and we
// wouldn't ever try to parse it
const invalidCertificate = `-----BEGIN CERTIFICATE-----
MIIBVDCCAQagAwIBAgIRANcos1c12CXTCm8qyZto2LswBQYDK2VwMDAxFTATBgNV
BAoTDGNlcnQtbWFuYWdlcjEXMBUGA1UEAxMOY21jdC10ZXN0LHhcNMjIxaaaaaaa
MjA1MTYyMjQyWhcNMzIxMjAyMTYyMjQyWjAwMRUwEwYDVQQKEwxjZXJ0LW1hbmFn
xFzAVBgNVBAMTDmNtY3QtdGVzdC1yb290MCowBQYDK2VwAyEAWjVDu9495KZ4aaa
g0YFJ94jggGrt3NFXWk6Mb51pCBylSyjNTAzMBIGA1UdEwEB/wQIMAYBAf8CAQMw
VR0OBBYEFFjCqrTVVpQRdBANLzgdKx3agWxIMAUGAytlcAEqb5PmhXtlAaaaaaaa
gySihG5glByO5ZajFBNBIhjOF6+yfN1Bo5XjJ7bGwVIhGoRPHCtbvsnfuQ5ySz95
CFD1BItRnQM=
-----END CERTIFICATE-----`

// #nosec G101 -- This is a test PK, ideally we would dynamically
// generate this pair, but this should not be a security risk.
const privateKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHThSpdYMjW1k4K2r8RwhIGmknKrr0XKQLOJeL2fVoxToAoGCCqGSM49
AwEHoUQDQgAEoMocv03WW/kCmyYM7CN7Ge7J5NOhJOKUYjF15NRBevWbxd8GYsvj
9yCaAWu1mIQpIuWI4pXHU9s4V0FDlIKerQ==
-----END EC PRIVATE KEY-----`
