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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

var (
	globalEnv *envtest.Environment
)

func CreateEnvtestEnvironment() *envtest.Environment {
	env := &envtest.Environment{
		UseExistingCluster: pointer.Bool(false),
		CRDDirectoryPaths: []string{
			"../../../deploy/charts/trust-manager/templates/trust.cert-manager.io_bundles.yaml",
		},
		Scheme: trustapi.GlobalScheme,
	}

	_, err := env.Start()
	Expect(err).NotTo(HaveOccurred())

	return env
}

func StopEnvtestEnvironment(env *envtest.Environment) {
	Expect(env.Stop()).NotTo(HaveOccurred())
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	//globalEnv = CreateEnvtestEnvironment()
})

var _ = AfterSuite(func() {
	//StopEnvtestEnvironment(globalEnv)
})
