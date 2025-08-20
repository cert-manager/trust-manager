/*
Copyright 2021 The cert-manager Authors.

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

package test

import (
	"testing"

	testenv "github.com/cert-manager/trust-manager/test/env"
)

// Test_Integration runs the full suite of tests for the Bundle controller.
func Test_Integration(t *testing.T) {
	testenv.RunSuite(t, "integration-clusterbundle", "../../../_artifacts")
}
