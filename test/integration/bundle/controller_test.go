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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/test/dummy"
	testenv "github.com/cert-manager/trust-manager/test/env"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

const (
	eventuallyTimeout      = testenv.EventuallyTimeout
	eventuallyPollInterval = testenv.EventuallyPollInterval
)

var _ = Describe("Integration", func() {
	var (
		ctx context.Context

		testBundle *trustapi.Bundle
		testData   testenv.TestData
	)

	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())

		By("Creating Bundle for test")
		testData = testenv.DefaultTrustData()
		testBundle = testenv.NewTestBundleConfigMapTarget(ctx, cl, trustNamespace, testData)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())
	})

	AfterEach(func() {
		By("Deleting test Bundle")
		Expect(cl.Delete(ctx, testBundle)).NotTo(HaveOccurred())
	})

	It("should update all targets when a ConfigMap source is added", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string]string{
				"new-source-key": dummy.TestCertificate4,
			},
		}
		Expect(cl.Create(ctx, configMap)).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: configMap.Name, Key: "new-source-key"},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys is added", func() {
		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
				"new-source-key-2": dummy.TestCertificate5,
			},
		}
		Expect(cl.Create(ctx, configMap)).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: configMap.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source is added", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"new-source-key": []byte(dummy.TestCertificate4),
			},
		}
		Expect(cl.Create(ctx, secret)).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: secret.Name, Key: "new-source-key"},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys is added", func() {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
				"new-source-key-2": []byte(dummy.TestCertificate5),
			},
		}
		Expect(cl.Create(ctx, secret)).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: secret.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when an inLine source is added", func() {
		newInLine := dummy.TestCertificate4

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{InLine: newInLine})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a default CA source is added", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{UseDefaultCAs: ptr.To(true)})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source is removed", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = []trustapi.BundleSource{testBundle.Spec.Sources[1], testBundle.Spec.Sources[2]}
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source is removed", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = []trustapi.BundleSource{
				testBundle.Spec.Sources[0],
				testBundle.Spec.Sources[2],
			}
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when an InLine source is removed", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = []trustapi.BundleSource{
				testBundle.Spec.Sources[0],
				testBundle.Spec.Sources[1],
			}
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source has been modified", func() {
		var configMap corev1.ConfigMap

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: trustNamespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}, &configMap)).NotTo(HaveOccurred())

		configMap.Data[testData.Sources.ConfigMap.Key] = dummy.TestCertificate4

		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys has a new key", func() {
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: secret.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		secret.Data["new-source-key-2"] = []byte(dummy.TestCertificate5)
		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys has a key removed", func() {
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
				"new-source-key-2": []byte(dummy.TestCertificate5),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: secret.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		delete(secret.Data, "new-source-key-2")
		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys has a key updated", func() {
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: secret.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		secret.Data["new-source-key-1"] = []byte(dummy.TestCertificate5)
		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source has been modified", func() {
		var secret corev1.Secret

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: trustNamespace, Name: testBundle.Spec.Sources[1].Secret.Name}, &secret)).NotTo(HaveOccurred())

		secret.Data[testData.Sources.Secret.Key] = []byte(dummy.TestCertificate4)

		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		expectedData := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys has a new key", func() {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: configMap.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		configMap.Data["new-source-key-2"] = dummy.TestCertificate5
		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys has a key removed", func() {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
				"new-source-key-2": dummy.TestCertificate5,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: configMap.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		delete(configMap.Data, "new-source-key-2")
		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys has a key updated", func() {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "new-bundle-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: configMap.Name, IncludeAllKeys: ptr.To(true)},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		configMap.Data["new-source-key-1"] = dummy.TestCertificate5
		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		expectedData = dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when an InLine source has been modified", func() {
		newInLine := dummy.TestCertificate4

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources[2].InLine = newInLine
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should delete old targets and update to new ones when the Spec.Target is modified", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Target = trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "changed-target-key"},
			}
		})()).To(Succeed())

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())

		var namespaceList corev1.NamespaceList
		Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())

		for _, namespace := range namespaceList.Items {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}

			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

			Expect(configMap.Data).To(MatchAllKeys(Keys{
				"changed-target-key": Equal(dummy.DefaultJoinedCerts()),
			}), "Ensuring old target Key has been replaced with the new target Key")
		}
	})

	It("should delete old targets and update to new ones when a JKS file is requested in the target", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Target = trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: testData.Target.Key},
				AdditionalFormats: &trustapi.AdditionalFormats{
					JKS: &trustapi.JKS{
						KeySelector: trustapi.KeySelector{
							Key: "myfile.jks",
						},
					},
				},
			}
		})()).To(Succeed())

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())

		var namespaceList corev1.NamespaceList
		Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())

		for _, namespace := range namespaceList.Items {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}

			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

			jksData, exists := configMap.BinaryData["myfile.jks"]
			Expect(exists).To(BeTrue(), "should find an entry called myfile.jks")

			Expect(testenv.CheckJKSFileSynced(jksData, trustapi.DefaultJKSPassword, dummy.DefaultJoinedCerts())).ToNot(HaveOccurred())
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
				Controller:         ptr.To(true),
				BlockOwnerDeletion: ptr.To(true),
			})
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "ensuring owner references were re-added correctly")
	})

	It("should revert modifications to target ConfigMap data", func() {
		var configMap corev1.ConfigMap
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

		configMap.Data[testData.Target.Key] = "CHANGED DATA"
		Expect(cl.Update(ctx, &configMap)).ToNot(HaveOccurred())

		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

			return apiequality.Semantic.DeepEqual(configMap.Data, map[string]string{testData.Target.Key: dummy.DefaultJoinedCerts()})
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "checking that the data is written back to the target")

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

		delete(configMap.Data, testData.Target.Key)

		Expect(cl.Update(ctx, &configMap)).ToNot(HaveOccurred())

		Eventually(func() bool {
			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())

			return apiequality.Semantic.DeepEqual(configMap.Data, map[string]string{testData.Target.Key: dummy.DefaultJoinedCerts()})
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "checking that the data is written back to the target")
	})

	It("should only write to Namespaces where the namespace selector matches", func() {
		// Create a new namespace for this test; GenerateName will populate the name after creation
		// We use GenerateName to create a new uniquely-named namespace that shouldn't clash with any of
		// the existing ones.
		testNamespace := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "trust-bundle-integration-ns-",
			},
		}
		Expect(cl.Create(ctx, &testNamespace)).NotTo(HaveOccurred())

		expectedData := dummy.DefaultJoinedCerts()

		// confirm all namespaces - including the new one - have the expected data
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)

		// add a label selector to the Bundle which should exclude all namespaces
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Target.NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{"foo": "bar"},
			}
		})()).To(Succeed())

		// confirm that the new namespace doesn't contain the config map any more
		// (no namespace should contain it but for brevity, only check the new one)
		Eventually(func() bool {
			var cm corev1.ConfigMap
			return apierrors.IsNotFound(cl.Get(ctx, client.ObjectKey{Namespace: testNamespace.Name, Name: testBundle.Name}, &cm))
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "checking that the new namespace without the label no longer has the ConfigMap")

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(&testNamespace), &testNamespace)).ToNot(HaveOccurred())

		// add the matching label to the new namespace
		testNamespace.Labels["foo"] = "bar"
		Expect(cl.Update(ctx, &testNamespace)).ToNot(HaveOccurred())

		// confirm that the new namespace now contains the bundle
		Eventually(func() error {
			return testenv.CheckBundleSynced(ctx, cl, testBundle.Name, testNamespace.Name, expectedData)
		}, eventuallyTimeout, eventuallyPollInterval).Should(Succeed(), "checking that bundle was re-added to newly labelled namespace")
	})

	Context("Reconcile consistency", func() {
		It("should have stable resourceVersion", func() {
			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: "kube-system", Name: testBundle.Name}, &configMap)).To(Succeed())
			resourceVersion := configMap.ResourceVersion
			Consistently(komega.Object(&configMap)).Should(HaveField("ObjectMeta.ResourceVersion", Equal(resourceVersion)))
		})

		It("should have stable resourceVersion for JKS target", func() {
			Expect(komega.Update(testBundle, func() {
				testBundle.Spec.Target.AdditionalFormats = &trustapi.AdditionalFormats{
					JKS: &trustapi.JKS{KeySelector: trustapi.KeySelector{Key: "target.jks"}}}
			})()).To(Succeed())

			configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: testBundle.Name}}
			Eventually(komega.Object(configMap)).Should(HaveField("BinaryData", HaveKey("target.jks")))

			resourceVersion := configMap.ResourceVersion
			Consistently(komega.Object(configMap)).Should(HaveField("ObjectMeta.ResourceVersion", Equal(resourceVersion)))
		})

		It("should have stable resourceVersion for PKCS12 target", func() {
			Expect(komega.Update(testBundle, func() {
				testBundle.Spec.Target.AdditionalFormats = &trustapi.AdditionalFormats{
					PKCS12: &trustapi.PKCS12{KeySelector: trustapi.KeySelector{Key: "target.p12"}}}
			})()).To(Succeed())

			configMap := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: testBundle.Name}}
			Eventually(komega.Object(configMap)).Should(HaveField("BinaryData", HaveKey("target.p12")))

			resourceVersion := configMap.ResourceVersion
			Consistently(komega.Object(configMap)).Should(HaveField("ObjectMeta.ResourceVersion", Equal(resourceVersion)))
		})
	})

	It("should add target annotations when added to a bundle", func() {
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Target.ConfigMap.Metadata = trustapi.TargetMetadata{
				Annotations: map[string]string{
					"test1": "test1",
				},
			}
		})()).To(Succeed())

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())

		var namespaceList corev1.NamespaceList
		Expect(cl.List(ctx, &namespaceList)).ToNot(HaveOccurred())

		for _, namespace := range namespaceList.Items {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}

			var configMap corev1.ConfigMap
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: testBundle.Name}, &configMap)).ToNot(HaveOccurred())
			Expect(configMap.Annotations).To(HaveKeyWithValue("test1", "test1"), "Ensuring target contains additional annotations")
		}
	})
})

// generateShortLivedCA creates a self-signed CA certificate PEM with the given lifetime.
func generateShortLivedCA(cn string, lifetime time.Duration) string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"cert-manager"}},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())

	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
}

var _ = Describe("Integration keepCertHistory", func() {
	var ctx context.Context

	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())
	})

	It("should retain previous cert after rotation and prune after expiry", func() {
		shortLivedCert := generateShortLivedCA("short-lived-ca", 30*time.Second)

		By("Creating a Secret source with a short-lived CA cert")
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "history-source-",
				Namespace:    trustNamespace,
			},
			Data: map[string][]byte{
				"ca.crt": []byte(shortLivedCert),
			},
		}
		Expect(cl.Create(ctx, secret)).NotTo(HaveOccurred())

		By("Creating a Bundle with keepCertHistory enabled")
		bundle := &trustapi.Bundle{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "history-bundle-",
			},
			Spec: trustapi.BundleSpec{
				Sources: []trustapi.BundleSource{
					{
						Secret: &trustapi.SourceObjectKeySelector{
							Name:            secret.Name,
							Key:             "ca.crt",
							KeepCertHistory: true,
						},
					},
				},
				Target: trustapi.BundleTarget{
					ConfigMap: &trustapi.TargetTemplate{Key: "bundle.pem"},
				},
			},
		}
		Expect(cl.Create(ctx, bundle)).NotTo(HaveOccurred())
		defer func() {
			Expect(cl.Delete(ctx, bundle)).NotTo(HaveOccurred())
		}()

		By("Waiting for initial sync with the short-lived cert")
		Eventually(func() error {
			return testenv.CheckBundleSyncedAllNamespaces(ctx, cl, bundle.Name, shortLivedCert)
		}, eventuallyTimeout, eventuallyPollInterval).Should(Succeed())

		findHistory := func(history []trustapi.SourceCertHistory, key string) *trustapi.SourceCertHistory {
			for i := range history {
				if history[i].SourceKey == key {
					return &history[i]
				}
			}
			return nil
		}

		By("Verifying status has history tracking for the source")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Name: bundle.Name}, bundle)).NotTo(HaveOccurred())
			key := "secret/" + secret.Name + "/ca.crt"
			entry := findHistory(bundle.Status.CertHistory, key)
			return entry != nil && entry.LastSeenFingerprint != "" && len(entry.Entries) == 0
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "status should have history with lastSeenFingerprint set and no entries yet")

		By("Rotating the Secret to a new long-lived cert")
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: trustNamespace, Name: secret.Name}, secret)).NotTo(HaveOccurred())
		secret.Data["ca.crt"] = []byte(dummy.TestCertificate4)
		Expect(cl.Update(ctx, secret)).NotTo(HaveOccurred())

		By("Verifying bundle contains both old and new certs after rotation")
		Eventually(func() error {
			return testenv.CheckBundleSyncedAllNamespacesContains(ctx, cl, bundle.Name, shortLivedCert)
		}, eventuallyTimeout, eventuallyPollInterval).Should(Succeed(), "bundle should contain old short-lived cert")
		Eventually(func() error {
			return testenv.CheckBundleSyncedAllNamespacesContains(ctx, cl, bundle.Name, dummy.TestCertificate4)
		}, eventuallyTimeout, eventuallyPollInterval).Should(Succeed(), "bundle should contain new cert")

		By("Verifying status has the old cert in history entries")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Name: bundle.Name}, bundle)).NotTo(HaveOccurred())
			key := "secret/" + secret.Name + "/ca.crt"
			entry := findHistory(bundle.Status.CertHistory, key)
			return entry != nil && len(entry.Entries) == 1
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "status should have one historical entry after rotation")

		By("Waiting for the short-lived cert to expire")
		time.Sleep(35 * time.Second)

		By("Triggering reconcile by updating the Secret")
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: trustNamespace, Name: secret.Name}, secret)).NotTo(HaveOccurred())
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations["trust-manager.io/force-reconcile"] = time.Now().String()
		Expect(cl.Update(ctx, secret)).NotTo(HaveOccurred())

		By("Verifying expired cert is pruned from history and bundle")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Name: bundle.Name}, bundle)).NotTo(HaveOccurred())
			key := "secret/" + secret.Name + "/ca.crt"
			entry := findHistory(bundle.Status.CertHistory, key)
			return entry != nil && len(entry.Entries) == 0
		}, eventuallyTimeout, eventuallyPollInterval).Should(BeTrue(), "expired entry should be pruned from history")

		By("Verifying bundle now only contains the new cert")
		Eventually(func() error {
			return testenv.CheckBundleSyncedAllNamespaces(ctx, cl, bundle.Name, dummy.TestCertificate4)
		}, eventuallyTimeout, eventuallyPollInterval).Should(Succeed(), "bundle should only contain the new cert after expiry")
	})
})
