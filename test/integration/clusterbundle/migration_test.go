/*
Copyright 2025 The cert-manager Authors.

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
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	"github.com/cert-manager/trust-manager/test"
	"github.com/cert-manager/trust-manager/test/dummy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClusterBundle Migration", func() {
	var (
		ctx           context.Context
		cl            client.Client
		bundle        *trustapi.Bundle
		clusterBundle *trustmanagerapi.ClusterBundle
	)
	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())

		var err error
		cl, err = client.New(env.Config, client.Options{
			Scheme: test.Scheme,
		})
		Expect(err).NotTo(HaveOccurred())

		bundle = &trustapi.Bundle{}
		bundle.GenerateName = "migration-"
		bundle.Spec.Sources = []trustapi.BundleSource{{InLine: ptr.To(dummy.TestCertificate4)}}
		bundle.Spec.Target = trustapi.BundleTarget{
			ConfigMap: &trustapi.TargetTemplate{
				Key: "ca.crt",
			},
			AdditionalFormats: &trustapi.AdditionalFormats{
				JKS: &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: "ca.jks",
					},
				},
			},
		}

		clusterBundle = &trustmanagerapi.ClusterBundle{}

		Expect(cl.Create(ctx, bundle)).To(Succeed())
	})

	It("should convert Bundle to ClusterBundle", func() {
		Eventually(func() ([]metav1.Condition, error) {
			if err := cl.Get(ctx, client.ObjectKeyFromObject(bundle), bundle); err != nil {
				return nil, err
			}
			return bundle.Status.Conditions, nil
		}).Should(HaveLen(1))
		condition := bundle.Status.Conditions[0]
		Expect(condition.Type).To(Equal(trustapi.BundleConditionDeprecated))
		Expect(condition.Status).To(Equal(metav1.ConditionTrue))

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(bundle), clusterBundle)).To(Succeed())
		Expect(clusterBundle.Spec.InLineCAs).To(Equal(ptr.To(dummy.TestCertificate4)))
		By("Ensuring additional JKS target is converted correctly with internal support annotation", func() {
			Expect(clusterBundle.Spec.Target.ConfigMap).To(Not(BeNil()))
			Expect(clusterBundle.Spec.Target.ConfigMap.Data).To(ConsistOf(
				trustmanagerapi.TargetKeyValue{
					Key: "ca.crt",
				},
				trustmanagerapi.TargetKeyValue{
					Key:    "ca.jks",
					Format: trustmanagerapi.BundleFormatPKCS12,
					PKCS12: trustmanagerapi.PKCS12{
						Password: ptr.To(trustapi.DefaultJKSPassword),
					},
				},
			))
			Expect(clusterBundle.Annotations).To(HaveKeyWithValue(trustapi.AnnotationKeyJKSKey, "ca.jks"))
		})
		Expect(clusterBundle.OwnerReferences).To(Equal([]metav1.OwnerReference{{
			APIVersion:         "trust.cert-manager.io/v1alpha1",
			Kind:               "Bundle",
			Name:               bundle.Name,
			UID:                bundle.UID,
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		}}))
	})

	It("should unmanage ClusterBundle when user migrates", func() {
		Eventually(func() error {
			return cl.Get(ctx, client.ObjectKeyFromObject(bundle), clusterBundle)
		}).Should(Succeed())
		Expect(clusterBundle.Spec.InLineCAs).ToNot(BeNil())

		clusterBundle.Annotations = map[string]string{
			trustmanagerapi.BundleMigratedAnnotation: "true",
		}
		clusterBundle.Spec.DefaultCAs = &trustmanagerapi.DefaultCAsSource{Provider: trustmanagerapi.DefaultCAsProviderSystem}
		Expect(cl.Update(ctx, clusterBundle)).To(Succeed())

		Eventually(func() (string, error) {
			if err := cl.Get(ctx, client.ObjectKeyFromObject(bundle), bundle); err != nil {
				return "", err
			}
			if len(bundle.Status.Conditions) != 1 {
				return "", fmt.Errorf("expected 1 condition, found %d", len(bundle.Status.Conditions))
			}
			return bundle.Status.Conditions[0].Type, nil
		}).Should(Equal(trustapi.BundleConditionMigrated))

		Expect(cl.Get(ctx, client.ObjectKeyFromObject(clusterBundle), clusterBundle)).To(Succeed())
		Expect(clusterBundle.OwnerReferences).To(BeEmpty())
		Expect(clusterBundle.Spec.InLineCAs).To(BeNil())
	})
})
