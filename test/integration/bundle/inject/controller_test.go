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

package inject

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	"github.com/cert-manager/trust-manager/pkg/bundle/inject"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Injector", func() {
	var namespace string

	BeforeEach(func() {
		ctx = context.Background()

		ns := &corev1.Namespace{}
		ns.GenerateName = "inject-"
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())
		namespace = ns.Name
	})

	It("should inject bundle data when ConfigMap labeled", func() {
		cm := &corev1.ConfigMap{}
		cm.GenerateName = "cm-"
		cm.Namespace = namespace
		cm.Labels = map[string]string{
			inject.BundleInjectLabelKey: "foo-bundle",
			"app":                       "my-app",
		}
		cm.Data = map[string]string{
			"tls.crt": "bar",
			"tls.key": "baz",
		}
		Expect(k8sClient.Create(ctx, cm)).To(Succeed())

		// Wait for ConfigMap to be processed by controller
		Eventually(komega.Object(cm)).Should(HaveField("Data", HaveKeyWithValue("ca.crt", "bundle data")))
		Expect(cm.Labels).To(HaveKeyWithValue("app", "my-app"))

		By("removing label from ConfigMap, it should remove bundle data", func() {
			Expect(komega.Update(cm, func() {
				delete(cm.Labels, inject.BundleInjectLabelKey)
			})()).To(Succeed())

			// Wait for ConfigMap to be processed by controller
			Eventually(komega.Object(cm)).Should(HaveField("Data", Not(HaveKey("ca.crt"))))
			Expect(cm.Labels).To(HaveKeyWithValue("app", "my-app"))
			Expect(cm.Data).To(Equal(map[string]string{
				"tls.crt": "bar",
				"tls.key": "baz",
			}))
		})
	})
})
