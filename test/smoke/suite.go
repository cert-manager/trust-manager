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
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle"
	"github.com/cert-manager/trust-manager/test/dummy"
	"github.com/cert-manager/trust-manager/test/env"
)

const (
	eventuallyTimeout = "10s"
)

var _ = Describe("Smoke", func() {
	It("should create a bundle, sync to target, and then remove all when deleted", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cl, err := client.New(cnf.RestConfig, client.Options{
			Scheme: trustapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating Bundle for test")
		testData := env.DefaultTrustData()

		testBundle := env.NewTestBundle(ctx, cl, bundle.Options{
			Log:       klogr.New(),
			Namespace: cnf.TrustNamespace,
		}, testData)

		By("Ensuring the Bundle has Synced")
		Eventually(func() bool {
			return env.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())
		}, eventuallyTimeout, "100ms").Should(BeTrue())

		By("Ensuring targets update when a ConfigMap source is updated")
		var configMap corev1.ConfigMap

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}, &configMap)).NotTo(HaveOccurred())

		configMap.Data[testData.Sources.ConfigMap.Key] = dummy.TestCertificate4

		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())
		Context("should observe Bundle has updated the certificate from the ConfigMap", func() {
			Eventually(func() bool {
				return env.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.JoinCerts(dummy.TestCertificate4, dummy.TestCertificate2, dummy.TestCertificate3))
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Ensuring targets update when a Secret source is updated")
		var secret corev1.Secret

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[1].Secret.Name}, &secret)).NotTo(HaveOccurred())

		secret.Data[testData.Sources.Secret.Key] = []byte(dummy.TestCertificate1)

		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())
		Context("should observe Bundle has updated the certificate from the Secret", func() {
			Eventually(func() bool {
				return env.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.JoinCerts(dummy.TestCertificate4, dummy.TestCertificate1, dummy.TestCertificate3))
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Ensuring targets update when an InLine source is updated")
		Expect(cl.Get(ctx, client.ObjectKey{Name: testBundle.Name}, testBundle)).NotTo(HaveOccurred())

		testBundle.Spec.Sources[2].InLine = pointer.String(dummy.TestCertificate2)

		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		newBundle := dummy.JoinCerts(dummy.TestCertificate4, dummy.TestCertificate1, dummy.TestCertificate2)

		Context("should observe Bundle has changed the certificate that was passed InLine", func() {
			Eventually(func() bool {
				return env.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, newBundle)
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Ensuring targets update when a Namespace is created")
		testNamespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-test-smoke-random-namespace-"}}

		Expect(cl.Create(ctx, &testNamespace)).NotTo(HaveOccurred())

		Context("should observe Bundle has created ConfigMap in testNamespace", func() {
			Eventually(func() bool {
				return env.BundleHasSynced(ctx, cl, testBundle.Name, testNamespace.Name, newBundle)
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Setting Namespace Selector should remove ConfigMaps from Namespaces that do not have a match")
		Expect(cl.Get(ctx, client.ObjectKey{Name: testBundle.Name}, testBundle)).NotTo(HaveOccurred())
		testBundle.Spec.Target.NamespaceSelector = &trustapi.NamespaceSelector{
			MatchLabels: map[string]string{"foo": "bar"},
		}
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())
		Context("should delete ConfigMap in test Namespace", func() {
			Eventually(func() bool {
				var cm corev1.ConfigMap
				err := cl.Get(ctx, client.ObjectKey{Namespace: testNamespace.Name, Name: testBundle.Name}, &cm)
				return apierrors.IsNotFound(err)
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Adding matching label on Namespace should sync ConfigMap to namespace")
		Expect(cl.Get(ctx, client.ObjectKey{Name: testNamespace.Name}, &testNamespace)).NotTo(HaveOccurred())

		testNamespace.Labels["foo"] = "bar"

		Expect(cl.Update(ctx, &testNamespace)).NotTo(HaveOccurred())
		Context("should create ConfigMap in test Namespace", func() {
			Eventually(func() bool {
				return env.BundleHasSynced(ctx, cl, testBundle.Name, testNamespace.Name, newBundle)
			}, eventuallyTimeout, "100ms").Should(BeTrue())
		})

		By("Deleting test Namespace")
		Expect(cl.Delete(ctx, &testNamespace)).NotTo(HaveOccurred())

		By("Deleting the Bundle created")
		Expect(cl.Get(ctx, client.ObjectKeyFromObject(testBundle), testBundle)).ToNot(HaveOccurred())
		Expect(cl.Delete(ctx, testBundle)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}})).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[1].Secret.Name}})).NotTo(HaveOccurred())

		By("Ensuring all targets have been deleted")
		var namespaceList corev1.NamespaceList
		Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())
		for _, namespace := range namespaceList.Items {
			Eventually(func() error {
				return cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, new(corev1.ConfigMap))
			}, eventuallyTimeout, "100ms").ShouldNot(BeNil())
		}
	})
})
