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

package fspkg

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cert-manager/trust-manager/test/dummy"
)

func quickJSONFromPackage(p Package) *bytes.Buffer {
	out, err := json.Marshal(p)
	if err != nil {
		panic("invalid test; failed to marshal JSON in quickJSONFromPackage")
	}

	return bytes.NewBuffer(out)
}

func Test_LoadPackage(t *testing.T) {
	// ensure that LoadPackage rejects invalid JSON, invalid certificate bundles, etc

	tests := map[string]struct {
		testData *bytes.Buffer
		expError bool
	}{
		"invalid JSON is rejected": {
			testData: bytes.NewBufferString(`{"name: "asd"}`),
			expError: true,
		},
		"package with empty name is rejected": {
			testData: quickJSONFromPackage(Package{
				Name:    "",
				Version: "123",
				Bundle:  dummy.TestCertificate5,
			}),
			expError: true,
		},
		"package with empty version is rejected": {
			testData: quickJSONFromPackage(Package{
				Name:    "asd",
				Version: "",
				Bundle:  dummy.TestCertificate5,
			}),
			expError: true,
		},
		"package with invalid cert is rejected": {
			testData: quickJSONFromPackage(Package{
				Name:    "asd",
				Version: "123",
				Bundle:  "not-a-certificate",
			}),
			expError: true,
		},
		"valid package is loaded without error": {
			testData: quickJSONFromPackage(Package{
				Name:    "asd",
				Version: "123",
				Bundle:  dummy.TestCertificate5,
			}),
			expError: false,
		},
	}

	for name, testSpec := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := LoadPackage(testSpec.testData)
			if err != nil != testSpec.expError {
				t.Fatalf("expErr=%v, got=%v", testSpec.expError, err)
			}

			if testSpec.expError {
				return
			}
		})
	}
}
