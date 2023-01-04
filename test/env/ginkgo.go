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

package env

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/wait"
)

func init() {
	wait.ForeverTestTimeout = time.Second * 60
}

func RunSuite(t *testing.T, suiteName, artifactDir string) {
	gomega.RegisterFailHandler(ginkgo.Fail)

	// NB: ARTIFACTS is set in prow jobs to a location which prow uses when consuming reports
	// see: https://docs.prow.k8s.io/docs/jobs/#job-environment-variables
	if path := os.Getenv("ARTIFACTS"); len(path) > 0 {
		artifactDir = path
	}

	if err := os.MkdirAll(artifactDir, 0o775); err != nil {
		t.Fatalf("failed to ensure artifactDir %q exists to store reports in: %s", artifactDir, err.Error())
	}

	junitDestination := filepath.Join(artifactDir, fmt.Sprintf("junit-go-%s.xml", suiteName))

	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()

	// NB: CI is set in prow jobs
	// see: https://docs.prow.k8s.io/docs/jobs/#job-environment-variables
	if _, ci := os.LookupEnv("CI"); ci {
		reporterConfig.NoColor = true
		reporterConfig.Verbose = true
	}

	reporterConfig.JUnitReport = junitDestination

	suiteConfig.RandomizeAllSpecs = true

	ginkgo.RunSpecs(t, suiteName, suiteConfig, reporterConfig)
}
