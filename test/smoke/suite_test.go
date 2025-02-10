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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/options"
	"github.com/cert-manager/trust-manager/test/dummy"
	"github.com/cert-manager/trust-manager/test/env"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	eventuallyTimeout     = "10s"
	eventualyPollInterval = "100ms"
)

var _ = Describe("Smoke", func() {
	var (
		ctx    context.Context
		cancel func()
	)

	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())
		ctx, cancel = context.WithCancel(ctx)
	})

	AfterEach(func() {
		cancel()
	})

	It("should create a bundle, sync to ConfigMap target, and then remove all configmap targets when deleted", func() {
		cl, err := client.New(cnf.RestConfig, client.Options{
			Scheme: trustapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating Bundle for test")
		testData := env.DefaultTrustData()

		testBundle := env.NewTestBundleConfigMapTarget(ctx, cl, options.Bundle{
			Namespace: cnf.TrustNamespace,
		}, testData)

		By("Ensuring the Bundle has Synced")
		env.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())

		testBundleCommon(ctx, cl, testBundle)
	})

	It("should create a bundle, sync to Secret target, and then remove all secret targets when deleted", func() {
		cl, err := client.New(cnf.RestConfig, client.Options{
			Scheme: trustapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating Bundle for test")
		testData := env.DefaultTrustData()

		testBundle := env.NewTestBundleSecretTarget(ctx, cl, options.Bundle{
			Namespace: cnf.TrustNamespace,
		}, testData)

		By("Ensuring the Bundle has Synced")
		env.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())

		testBundleCommon(ctx, cl, testBundle)
	})
})

func testBundleCommon(ctx context.Context, cl client.Client, testBundle *trustapi.Bundle) {
	testData := env.DefaultTrustData()
	By("Ensuring targets update when a ConfigMap source is updated")
	var configMap corev1.ConfigMap

	Expect(cl.Get(ctx, client.ObjectKey{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}, &configMap)).NotTo(HaveOccurred())

	configMap.Data[testData.Sources.ConfigMap.Key] = dummy.TestCertificate4

	Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

	env.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate4, dummy.TestCertificate3))

	By("Ensuring targets update when a Secret source is updated")
	var secret corev1.Secret

	Expect(cl.Get(ctx, client.ObjectKey{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[1].Secret.Name}, &secret)).NotTo(HaveOccurred())

	secret.Data[testData.Sources.Secret.Key] = []byte(dummy.TestCertificate1)

	Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

	env.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3))

	By("Ensuring targets update when an InLine source is updated")
	Expect(cl.Get(ctx, client.ObjectKey{Name: testBundle.Name}, testBundle)).NotTo(HaveOccurred())

	testBundle.Spec.Sources[2].InLine = ptr.To(dummy.TestCertificate2)

	Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

	newBundle := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4)

	env.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, newBundle)

	By("Ensuring targets update when default CAs are requested")
	Expect(cl.Get(ctx, client.ObjectKey{Name: testBundle.Name}, testBundle)).NotTo(HaveOccurred())

	testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{UseDefaultCAs: ptr.To(true)})

	Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

	env.EventuallyBundleHasSyncedAllNamespacesContains(ctx, cl, testBundle.Name, newBundle)

	By("Ensuring targets update when a Namespace is created")
	testNamespace := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "trust-test-smoke-random-namespace-"}}

	Expect(cl.Create(ctx, &testNamespace)).NotTo(HaveOccurred())

	env.EventuallyBundleHasSyncedToNamespaceContains(ctx, cl, testBundle.Name, testNamespace.Name, newBundle)

	By("Setting Namespace Selector should remove Secrets from Namespaces that do not have a match")
	Expect(cl.Get(ctx, client.ObjectKey{Name: testBundle.Name}, testBundle)).NotTo(HaveOccurred())

	testBundle.Spec.Target.NamespaceSelector = &metav1.LabelSelector{
		MatchLabels: map[string]string{"foo": "bar"},
	}
	Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

	Eventually(func() bool {
		var err error
		if testBundle.Spec.Target.Secret != nil {
			var secret corev1.Secret
			err = cl.Get(ctx, client.ObjectKey{Namespace: testNamespace.Name, Name: testBundle.Name}, &secret)
		} else if testBundle.Spec.Target.ConfigMap != nil {
			var cm corev1.ConfigMap
			err = cl.Get(ctx, client.ObjectKey{Namespace: testNamespace.Name, Name: testBundle.Name}, &cm)
		}
		return apierrors.IsNotFound(err)
	}, eventuallyTimeout, eventualyPollInterval).Should(BeTrue(), "checking that namespace selector resulted in non-matching namespaces having Secret/ConfigMap removed")

	By("Adding matching label on Namespace should sync ConfigMap/Secret to namespace")
	Expect(cl.Get(ctx, client.ObjectKey{Name: testNamespace.Name}, &testNamespace)).NotTo(HaveOccurred())

	testNamespace.Labels["foo"] = "bar"

	Expect(cl.Update(ctx, &testNamespace)).NotTo(HaveOccurred())

	env.EventuallyBundleHasSyncedToNamespaceContains(ctx, cl, testBundle.Name, testNamespace.Name, newBundle)

	By("Deleting test Namespace")
	Expect(cl.Delete(ctx, &testNamespace)).NotTo(HaveOccurred())

	By("Deleting the created Bundle")
	Expect(cl.Get(ctx, client.ObjectKeyFromObject(testBundle), testBundle)).ToNot(HaveOccurred())

	Expect(cl.Delete(ctx, testBundle)).NotTo(HaveOccurred())

	Expect(cl.Delete(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}})).NotTo(HaveOccurred())

	Expect(cl.Delete(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: cnf.TrustNamespace, Name: testBundle.Spec.Sources[1].Secret.Name}})).NotTo(HaveOccurred())

	By("Ensuring all targets have been deleted")
	var namespaceList corev1.NamespaceList
	Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())

	for _, namespace := range namespaceList.Items {
		Eventually(func() error {
			if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, new(corev1.ConfigMap)); err != nil {
				return err
			}

			return cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, new(corev1.Secret))
		}, eventuallyTimeout, eventualyPollInterval).ShouldNot(Succeed())
	}
}
