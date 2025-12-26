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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/trust-manager/test/dummy"
)

func TestNewCertPool(t *testing.T) {
	certPool := NewCertPool(WithFilteredExpiredCerts(false))

	assert.NotNil(t, certPool)
}

func TestAppendCertFromPEM(t *testing.T) {
	tests := map[string]struct {
		pemData       string
		filterExpired bool
		expError      string
		expEmpty      bool
	}{
		"if single certificate, should return": {
			pemData: dummy.TestCertificate5,
		},
		"if multiple certificates, should return": {
			pemData: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3),
		},
		"if invalid certificate, should return empty bundle": {
			// invalid certificate
			pemData: `-----BEGIN CERTIFICATE-----
			MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
			TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
			cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
			WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
			ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
			MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
			h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
			0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
			A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW`,
			expEmpty: true,
		},
		"if invalid PEM data, should return empty bundle": {
			pemData:  "qwerty",
			expEmpty: true,
		},
		"if expired certificate, should return": {
			pemData: dummy.TestExpiredCertificate,
		},
		"if expired certificate with filter expired enabled, should return empty bundle": {
			pemData:       dummy.TestExpiredCertificate,
			filterExpired: true,
			expEmpty:      true,
		},
	}

	// populate certificates bundle
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			certPool := NewCertPool(WithFilteredExpiredCerts(test.filterExpired))

			err := certPool.AddCertsFromPEM([]byte(test.pemData))
			if test.expError != "" {
				assert.Error(t, err, test.expError)
			} else {
				assert.NoError(t, err)
			}

			certPEM := certPool.PEM()
			if len(certPEM) != 0 == (test.expEmpty) {
				t.Fatalf("error getting PEM certificates from pool: certificate data is nil")
			}
		})
	}
}

// CA certificates only
func TestAppendCACertFromPEM(t *testing.T) {
	tests := map[string]struct {
		pemData        string
		filterExpired  bool
		expError       string
		expEmpty       bool
		useCACertsOnly bool
		CACertsCount   int
	}{
		"if multiple certificates, should return": {
			pemData:      dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificateNonCA1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificateNonCA2),
			CACertsCount: 3,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			certPool := NewCertPool(WithCACertsOnly(true))

			err := certPool.AddCertsFromPEM([]byte(test.pemData))
			if test.expError != "" {
				assert.Error(t, err, test.expError)
			} else {
				assert.NoError(t, err)
			}

			CACertsList := certPool.Certificates()
			if len(CACertsList) != test.CACertsCount {
				t.Fatalf("The number of CA certificates isn't equal to expected one: given %d, expected %d", len(CACertsList), test.CACertsCount)
			}

			for _, cert := range CACertsList {
				if !cert.IsCA {
					t.Fatalf("there are nonCA certificates in the certificates list")
				}
			}
		})
	}
}
