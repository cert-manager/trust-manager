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

	"github.com/cert-manager/trust-manager/test/dummy"
)

func TestNewCertPool(t *testing.T) {
	certPool := newCertPool(false)

	if certPool == nil {
		t.Fatal("pool is nil")
	}
}

func TestCertificatesDeduplication(t *testing.T) {
	// create a pool
	certPool := newCertPool(false)

	// list of certificates
	certificateList := [...]struct {
		certificateName string
		certificate     string
	}{
		{
			"TestCertificate3Duplicate", // this certificate is duplicate of TestCertificate3
			dummy.TestCertificate3Duplicate,
		},
		{
			"TestCertificate1",
			dummy.TestCertificate1,
		},
		{
			"TestCertificate2",
			dummy.TestCertificate2,
		},
		{
			"TestCertificate3",
			dummy.TestCertificate3,
		},
		{
			"TestCertificate5Duplicate", // this certificate is duplicate of TestCertificate5
			dummy.TestCertificate5Duplicate,
		},
		{
			"TestCertificate4",
			dummy.TestCertificate4,
		},
		{
			"TestCertificate5",
			dummy.TestCertificate5,
		},
	}

	// certificates bundle structure
	certificateBundle := []struct {
		certificateName string
		certificate     string
	}{}

	// populate certificates bundle
	for _, crt := range certificateList {
		if !certPool.isCertificateDuplicate([]byte(crt.certificate)) {
			certificateBundle = append(certificateBundle, crt)
		}
	}

	// create a new pool
	newCertPool := newCertPool(false)

	// check certificates bundle for duplicated certificates
	for _, crt := range certificateBundle {
		if newCertPool.isCertificateDuplicate([]byte(crt.certificate)) {
			t.Errorf("duplicate certificate found %s\n", crt.certificateName)
		}
	}
}

func TestAppendCertFromPEM(t *testing.T) {
	// list of certificates
	certificateList := [...]struct {
		certificateName string
		certificate     string
		expectNil       bool
	}{
		{
			"TestCertificate5",
			dummy.TestCertificate5,
			false,
		},
		{
			"TestCertificateChain6",
			dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3),
			false,
		},
		{
			// invalid certificate
			"TestCertificateInvalid7",
			`-----BEGIN CERTIFICATE-----
			MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
			TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
			cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
			WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
			ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
			MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
			h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
			0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
			A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW`,
			true,
		},
		{
			"TestCertificateInvalid8",
			"qwerty",
			true,
		},
		{
			"TestExpiredCertificate",
			dummy.TestExpiredCertificate,
			false,
		},
	}

	// populate certificates bundle
	for _, crt := range certificateList {
		certPool := newCertPool(false)

		if err := certPool.appendCertFromPEM([]byte(crt.certificate)); err != nil {
			t.Fatalf("error adding PEM certificate into pool %s", err)
		}

		certPEM := certPool.getCertsPEM()
		if len(certPEM) != 0 == (crt.expectNil) {
			t.Fatalf("error getting PEM certificates from pool: certificate data is nil")
		}
	}
}
