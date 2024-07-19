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

	"github.com/stretchr/testify/require"

	"github.com/cert-manager/trust-manager/test/dummy"
)

func TestNewCertPool(t *testing.T) {
	certPool := NewCertPool(WithFilteredExpiredCerts(false))

	if certPool == nil {
		t.Fatal("pool is nil")
	}
}

func TestAppendCertFromPEM(t *testing.T) {
	// list of certificates
	certificateList := [...]struct {
		certificateName string
		certificate     string
		expectError     string
		expectNil       bool
	}{
		{
			certificateName: "TestCertificate5",
			certificate:     dummy.TestCertificate5,
			expectNil:       false,
		},
		{
			certificateName: "TestCertificateChain6",
			certificate:     dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3),
			expectNil:       false,
		},
		{
			// invalid certificate
			certificateName: "TestCertificateInvalid7",
			certificate: `-----BEGIN CERTIFICATE-----
			MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
			TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
			cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
			WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
			ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
			MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
			h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
			0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
			A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW`,
			expectError: "no non-expired certificates found in input bundle",
			expectNil:   true,
		},
		{
			certificateName: "TestCertificateInvalid8",
			certificate:     "qwerty",
			expectError:     "no non-expired certificates found in input bundle",
			expectNil:       true,
		},
		{
			certificateName: "TestExpiredCertificate",
			certificate:     dummy.TestExpiredCertificate,
			expectNil:       false,
		},
	}

	// populate certificates bundle
	for _, crt := range certificateList {
		certPool := NewCertPool(WithFilteredExpiredCerts(false))

		err := certPool.AddCertsFromPEM([]byte(crt.certificate))
		if crt.expectError != "" {
			require.Error(t, err)
			require.Equal(t, crt.expectError, err.Error())
			continue
		} else {
			require.NoError(t, err)
		}

		certPEM := certPool.PEM()
		if len(certPEM) != 0 == (crt.expectNil) {
			t.Fatalf("error getting PEM certificates from pool: certificate data is nil")
		}
	}
}
