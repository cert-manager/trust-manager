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
	"encoding/pem"
	"testing"
)

// This function is in a separate file so it can be shared between our tests
// which set GODEBUG and have different tags

func negativeSerialNumberCADER(t *testing.T) []byte {
	var block *pem.Block
	block, _ = pem.Decode([]byte(negativeSerialNumberCAPEM))

	if block == nil {
		t.Fatalf("invalid test: negativeSerialNumberCA isn't valid PEM data")
	}

	return block.Bytes
}
