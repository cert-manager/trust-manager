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
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust/pkg/bundle"
	testenv "github.com/cert-manager/trust/test/env"
)

const (
	eventuallyTimeout = "30s"
)

var _ = Describe("Integration", func() {
	var (
		ctx    context.Context
		cancel func()

		cl   client.Client
		mgr  manager.Manager
		opts bundle.Options

		testBundle *trustapi.Bundle
		testData   testenv.TestData
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		var err error
		cl, err = client.New(env.Config, client.Options{
			Scheme: trustapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-bunde-trust-",
			},
		}
		Expect(cl.Create(ctx, namespace)).NotTo(HaveOccurred())

		By("Created trust Namespace: " + namespace.Name)

		opts = bundle.Options{
			Log:       logf.Log,
			Namespace: namespace.Name,
		}

		mgr, err = ctrl.NewManager(env.Config, ctrl.Options{
			Scheme:                        trustapi.GlobalScheme,
			LeaderElection:                true,
			LeaderElectionNamespace:       opts.Namespace,
			NewCache:                      bundle.NewCacheFunc(opts),
			LeaderElectionID:              "cert-manager-trust",
			LeaderElectionReleaseOnCancel: true,
			Logger:                        logf.Log,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(bundle.AddBundleController(ctx, mgr, opts)).NotTo(HaveOccurred())

		By("Running Bundle controller")
		go mgr.Start(ctx)

		By("Waiting for Informers to Sync")
		Expect(mgr.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())

		By("Waiting for Leader Election")
		<-mgr.Elected()

		By("Creating Bundle for test")
		testData = testenv.DefaultTrustData()
		testBundle = testenv.NewTestBundle(ctx, cl, opts, testData)
		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
		Expect(cl.Get(ctx, client.ObjectKeyFromObject(testBundle), testBundle)).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		By("Deleting test Bundle")
		Expect(cl.Delete(ctx, testBundle)).NotTo(HaveOccurred())

		By("Deleting test trust Namespace: " + opts.Namespace)
		Expect(cl.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: opts.Namespace}})).ToNot(HaveOccurred())

		By("Stopping Bundle controller")
		cancel()
	})

	It("should update all targets when a ConfigMap source is added", func() {
		Expect(cl.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key": "D",
			},
		})).NotTo(HaveOccurred())

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(testBundle), testBundle)).ToNot(HaveOccurred())
		testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
			ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", KeySelector: trustapi.KeySelector{Key: "new-source-key"}},
		})
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nC\nD\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when a Secret source is added", func() {
		Expect(cl.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key": []byte("D"),
			},
		})).NotTo(HaveOccurred())

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(testBundle), testBundle)).ToNot(HaveOccurred())
		testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
			Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", KeySelector: trustapi.KeySelector{Key: "new-source-key"}},
		})
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nC\nD\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when an inLine source is added", func() {
		newInLine := "D"
		testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{InLine: &newInLine})
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nC\nD\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when a ConfigMap source is removed", func() {
		testBundle.Spec.Sources = []trustapi.BundleSource{testBundle.Spec.Sources[1], testBundle.Spec.Sources[2]}
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "B\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when a Secret source is removed", func() {
		testBundle.Spec.Sources = []trustapi.BundleSource{testBundle.Spec.Sources[0], testBundle.Spec.Sources[2]}
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when an InLine source is removed", func() {
		testBundle.Spec.Sources = []trustapi.BundleSource{testBundle.Spec.Sources[0], testBundle.Spec.Sources[1]}
		Expect(cl.Update(ctx, testBundle)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when a ConfigMap source has been modified", func() {
		var configMap corev1.ConfigMap
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}, &configMap)).NotTo(HaveOccurred())
		configMap.Data[testData.Sources.ConfigMap.Key] = "D"
		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "D\nB\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when a Secret source has been modified", func() {
		var secret corev1.Secret
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: testBundle.Spec.Sources[1].Secret.Name}, &secret)).NotTo(HaveOccurred())
		secret.Data[testData.Sources.Secret.Key] = []byte("D")
		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nD\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should update all targets when an InLine source has been modified", func() {
		newInLine := "D"
		testBundle.Spec.Sources[2].InLine = &newInLine
		Expect(cl.Update(ctx, testBundle)).ToNot(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nD\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should delete old targets and update to new ones when the Spec.Target is modified", func() {
		testBundle.Spec.Target = trustapi.BundleTarget{
			ConfigMap: &trustapi.KeySelector{Key: "changed-target-key"},
		}
		Expect(cl.Update(ctx, testBundle)).ToNot(HaveOccurred())
		Eventually(func() bool { return testenv.BundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, "A\nB\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())

		var namespaceList corev1.NamespaceList
		Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())
		for _, namespace := range namespaceList.Items {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}

			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
			Expect(configMap.Data).To(MatchAllKeys(Keys{
				"changed-target-key": Equal("A\nB\nC\n"),
			}), "Ensuring old target Key has been replaced with the new target Key")
		}
	})

	It("should re-add the owner reference of a target ConfigMap if it has been removed", func() {
		var configMap corev1.ConfigMap
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
		configMap.OwnerReferences = nil
		Expect(cl.Update(ctx, &configMap)).ToNot(HaveOccurred())

		Eventually(func() bool {
			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
			return len(configMap.OwnerReferences) == 1 && apiequality.Semantic.DeepEqual(configMap.OwnerReferences[0], metav1.OwnerReference{
				Kind:               "Bundle",
				APIVersion:         "trust.cert-manager.io/v1alpha1",
				UID:                testBundle.UID,
				Name:               testBundle.Name,
				Controller:         pointer.Bool(true),
				BlockOwnerDeletion: pointer.Bool(true),
			})
		}, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should revert modifications to target ConfigMap data", func() {
		var configMap corev1.ConfigMap
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
		configMap.Data[testData.Target.Key] = "CHANGED DATA"
		Expect(cl.Update(ctx, &configMap)).ToNot(HaveOccurred())

		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
			return apiequality.Semantic.DeepEqual(configMap.Data, map[string]string{testData.Target.Key: "A\nB\nC\n"})
		}, eventuallyTimeout, "100ms").Should(BeTrue())

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
		delete(configMap.Data, testData.Target.Key)
		Expect(cl.Update(ctx, &configMap)).ToNot(HaveOccurred())

		Eventually(func() bool {
			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
			return apiequality.Semantic.DeepEqual(configMap.Data, map[string]string{testData.Target.Key: "A\nB\nC\n"})
		}, eventuallyTimeout, "100ms").Should(BeTrue())
	})

	It("should only write to Namespaces where the namespace selector matches", func() {
		testNamespace := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "trust-test-smoke-random-namespace",
			},
		}

		Expect(cl.Create(ctx, &testNamespace)).NotTo(HaveOccurred())
		Eventually(func() bool { return testenv.BundleHasSynced(ctx, cl, testBundle.Name, testNamespace.Name, "A\nB\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())

		testBundle.Spec.Target.NamespaceSelector = &trustapi.NamespaceSelector{
			MatchLabels: map[string]string{"foo": "bar"},
		}

		Expect(cl.Update(ctx, testBundle)).ToNot(HaveOccurred())

		Eventually(func() bool {
			var cm corev1.ConfigMap
			return apierrors.IsNotFound(cl.Get(ctx, client.ObjectKey{Namespace: "trust-test-smoke-random-namespace", Name: testBundle.Name}, &cm))
		}, eventuallyTimeout, "100ms").Should(BeTrue())

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(&testNamespace), &testNamespace)).ToNot(HaveOccurred())

		testNamespace.Labels["foo"] = "bar"
		Expect(cl.Update(ctx, &testNamespace)).ToNot(HaveOccurred())

		Eventually(func() bool { return testenv.BundleHasSynced(ctx, cl, testBundle.Name, testNamespace.Name, "A\nB\nC\n") }, eventuallyTimeout, "100ms").Should(BeTrue())
	})
})
