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
	"encoding/json"
	"os"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test"
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
		ctx    context.Context
		cancel func()

		log logr.Logger

		cl         client.Client
		mgr        manager.Manager
		mgrStopped chan struct{}
		opts       controller.Options

		testBundle *trustapi.Bundle
		testData   testenv.TestData

		tmpFileName string
	)

	BeforeEach(func() {
		log, ctx = ktesting.NewTestContext(GinkgoT())
		ctx, cancel = context.WithCancel(ctx)

		var err error

		By("Writing default package")
		tmpFileName, err = writeDefaultPackage()
		Expect(err).NotTo(HaveOccurred())

		cl, err = client.New(env.Config, client.Options{
			Scheme: test.Scheme,
		})
		Expect(err).NotTo(HaveOccurred())
		komega.SetClient(cl)

		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-bunde-trust-",
			},
		}
		Expect(cl.Create(ctx, namespace)).NotTo(HaveOccurred())

		By("Created trust Namespace: " + namespace.Name)
		opts = controller.Options{
			Namespace:              namespace.Name,
			DefaultPackageLocation: tmpFileName,
		}

		By("Make sure that manager is not running")
		Expect(mgr).To(BeNil())

		ctrl.SetLogger(log)
		mgr, err = ctrl.NewManager(env.Config, ctrl.Options{
			Scheme: test.Scheme,
			// we don't need leader election for this test,
			// there should only be one test running at a time
			LeaderElection: false,
			Controller: config.Controller{
				// need to skip unique controller name validation
				// since all tests need a dedicated controller
				SkipNameValidation: ptr.To(true),
			},
			Cache: bundle.CacheOpts(controller.Options{}),
		})
		Expect(err).NotTo(HaveOccurred())

		mgrStopped = make(chan struct{})

		Expect(bundle.SetupWithManager(ctx, mgr, opts)).NotTo(HaveOccurred())

		By("Running Bundle controller")
		go func() {
			defer close(mgrStopped)

			err := mgr.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		}()

		By("Waiting for Informers to Sync")
		Expect(mgr.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())

		By("Waiting for Leader Election")
		<-mgr.Elected()

		By("Creating Bundle for test")
		testData = testenv.DefaultTrustData()
		testBundle = testenv.NewTestBundleConfigMapTarget(ctx, cl, opts, testData)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, dummy.DefaultJoinedCerts())
	})

	AfterEach(func() {
		By("Deleting test Bundle")
		Expect(cl.Delete(ctx, testBundle)).NotTo(HaveOccurred())

		By("Deleting test trust Namespace: " + opts.Namespace)
		Expect(cl.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: opts.Namespace}})).ToNot(HaveOccurred())

		By("Stopping Bundle controller")
		cancel()

		By("Removing default package")
		Expect(os.Remove(tmpFileName)).ToNot(HaveOccurred())

		<-mgrStopped
		// set to nil to indicate that the manager has been stopped
		mgr = nil
	})

	It("should update all targets when a ConfigMap source is added", func() {
		Expect(cl.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key": dummy.TestCertificate4,
			},
		})).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", Key: "new-source-key"},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys is added", func() {
		Expect(cl.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
				"new-source-key-2": dummy.TestCertificate5,
			},
		})).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source is added", func() {
		Expect(cl.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key": []byte(dummy.TestCertificate4),
			},
		})).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", Key: "new-source-key"},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys is added", func() {
		Expect(cl.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
				"new-source-key-2": []byte(dummy.TestCertificate5),
			},
		})).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3, dummy.TestCertificate5)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when an inLine source is added", func() {
		newInLine := dummy.TestCertificate4

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{InLine: &newInLine})
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

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: testBundle.Spec.Sources[0].ConfigMap.Name}, &configMap)).NotTo(HaveOccurred())

		configMap.Data[testData.Sources.ConfigMap.Key] = dummy.TestCertificate4

		Expect(cl.Update(ctx, &configMap)).NotTo(HaveOccurred())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a ConfigMap source including all keys has a new key", func() {
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
				"new-source-key-2": []byte(dummy.TestCertificate5),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string][]byte{
				"new-source-key-1": []byte(dummy.TestCertificate4),
			},
		}

		Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				Secret: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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

		Expect(cl.Get(ctx, client.ObjectKey{Namespace: opts.Namespace, Name: testBundle.Spec.Sources[1].Secret.Name}, &secret)).NotTo(HaveOccurred())

		secret.Data[testData.Sources.Secret.Key] = []byte(dummy.TestCertificate4)

		Expect(cl.Update(ctx, &secret)).NotTo(HaveOccurred())

		expectedData := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3)

		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})

	It("should update all targets when a Secret source including all keys has a new key", func() {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
				"new-source-key-2": dummy.TestCertificate5,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key-1": dummy.TestCertificate4,
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())
		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", IncludeAllKeys: true},
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
			testBundle.Spec.Sources[2].InLine = &newInLine
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
			testBundle.Spec.Target.ConfigMap.Metadata = &trustapi.TargetMetadata{
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

	It("should update all targets with CA certificates only", func() {
		configMap := corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "new-bundle-source",
				Namespace: opts.Namespace,
			},
			Data: map[string]string{
				"new-source-key": dummy.JoinCerts(dummy.TestCertificateNonCA1),
			},
		}

		Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())

		Expect(komega.Update(testBundle, func() {
			testBundle.Spec.UseCACertsOnly = ptr.To(true)
			testBundle.Spec.Sources = append(testBundle.Spec.Sources, trustapi.BundleSource{
				ConfigMap: &trustapi.SourceObjectKeySelector{Name: "new-bundle-source", Key: "new-source-key"},
			})
		})()).To(Succeed())

		expectedData := dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3)
		testenv.EventuallyBundleHasSyncedAllNamespaces(ctx, cl, testBundle.Name, expectedData)
	})
})

func writeDefaultPackage() (string, error) {
	file, err := os.CreateTemp("", "trust-manager-suite-*.json")
	if err != nil {
		return "", err
	}

	defer file.Close()

	pkg := &fspkg.Package{
		Name:    "asd",
		Version: "123",
		Bundle:  dummy.TestCertificate5,
	}

	serialized, err := json.Marshal(pkg)
	if err != nil {
		return "", err
	}

	_, err = file.Write(serialized)
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}
