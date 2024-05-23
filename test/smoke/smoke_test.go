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

package smoke

import (
	"flag"
	"testing"

	"github.com/cert-manager/trust-manager/test/env"
	"github.com/cert-manager/trust-manager/test/smoke/config"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	cnf *config.Config
)

func init() {
	// subtle: Flags need to be registered in an init function when Ginkgo is used.
	// If not, go test will call flag.Parse before ginkgo runs and our custom args will
	// not be respected
	cnf = config.New(flag.CommandLine)
}

var _ = BeforeSuite(func() {
	Expect(cnf.Complete()).NotTo(HaveOccurred())
})

// Test_Smoke runs the full suite of smoke tests against trust.cert-manager.io
func Test_Smoke(t *testing.T) {
	env.RunSuite(t, "smoke-trust", "../../_artifacts")
}
