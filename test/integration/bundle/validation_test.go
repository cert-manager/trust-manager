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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Bundle Validation", func() {
	var (
		ctx    context.Context
		cl     client.Client
		bundle *trustapi.Bundle
	)
	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())

		var err error
		cl, err = client.New(env.Config, client.Options{
			Scheme: test.Scheme,
		})
		Expect(err).NotTo(HaveOccurred())

		bundle = &trustapi.Bundle{}
		bundle.GenerateName = "validation-"
		bundle.Spec.Sources = []trustapi.BundleSource{{
			UseDefaultCAs: ptr.To(true),
		}}
		bundle.Spec.Target = trustapi.BundleTarget{ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt"}}
	})

	Context("Sources", func() {
		It("should require sources", func() {
			bundle.Spec.Sources = nil

			expectedErr := "spec.sources: Required value"
			Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
		})

		It("should require at most one useDefaultCAs source", func() {
			bundle.Spec.Sources = []trustapi.BundleSource{
				{UseDefaultCAs: ptr.To(true)},
				{UseDefaultCAs: ptr.To(true)},
			}

			expectedErr := "spec.sources: Forbidden: must request default CAs either once or not at all but got 2 requests"
			Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
		})
	})

	Context("Source item", func() {
		DescribeTable("should require exactly one source",
			func(source trustapi.BundleSource, wantErr string) {
				bundle.Spec.Sources = []trustapi.BundleSource{source}
				if wantErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(wantErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when none set", trustapi.BundleSource{}, "spec.sources[0]: Invalid value: exactly one of the fields in [configMap secret inLine useDefaultCAs] must be set"),
			Entry("when configMap set", trustapi.BundleSource{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "ca", Key: "ca.crt"}}, ""),
			Entry("when secret set", trustapi.BundleSource{Secret: &trustapi.SourceObjectKeySelector{Name: "ca", Key: "ca.crt"}}, ""),
			Entry("when inLine set", trustapi.BundleSource{InLine: ptr.To("cert-placeholder")}, ""),
			Entry("when useDefaultCAs=true set", trustapi.BundleSource{UseDefaultCAs: ptr.To(true)}, ""),
			Entry("when useDefaultCAs=false set", trustapi.BundleSource{UseDefaultCAs: ptr.To(false)}, "spec.sources: Forbidden: must define at least one source"),
			Entry("when multiple set", trustapi.BundleSource{InLine: ptr.To("cert-placeholder"), UseDefaultCAs: ptr.To(true)}, "spec.sources[0]: Invalid value: exactly one of the fields in [configMap secret inLine useDefaultCAs] must be set"),
		)
	})

	Context("Source object item", func() {
		var (
			selectorAccessor func(*trustapi.SourceObjectKeySelector)
			field            string
		)

		BeforeEach(func() {
			bundle.Spec.Sources = []trustapi.BundleSource{{}}
		})

		sourceObjectAsserts := func() {
			DescribeTable("should require exactly one object specifier",
				func(selector *trustapi.SourceObjectKeySelector, wantErr bool) {
					selector.Key = "ca.crt"
					selectorAccessor(selector)
					if wantErr {
						expectedErr := "Invalid value: exactly one of the fields in [name selector] must be set"
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when none set", &trustapi.SourceObjectKeySelector{}, true),
				Entry("when name set", &trustapi.SourceObjectKeySelector{Name: "ca"}, false),
				Entry("when selector set", &trustapi.SourceObjectKeySelector{Selector: &metav1.LabelSelector{}}, false),
				Entry("when both set", &trustapi.SourceObjectKeySelector{Name: "ca", Selector: &metav1.LabelSelector{}}, true),
			)

			DescribeTable("should require exactly one key specifier",
				func(selector *trustapi.SourceObjectKeySelector, wantErr string) {
					selector.Name = "ca"
					selectorAccessor(selector)
					if wantErr != "" {
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(wantErr, field)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when none set", &trustapi.SourceObjectKeySelector{}, "Invalid value: \"key: ' ', includeAllKeys: false\": source %s key must be defined when includeAllKeys is false"),
				Entry("when key set", &trustapi.SourceObjectKeySelector{Key: "ca.crt"}, ""),
				Entry("when includeAllKeys set to true", &trustapi.SourceObjectKeySelector{IncludeAllKeys: ptr.To(true)}, ""),
				Entry("when includeAllKeys set to false", &trustapi.SourceObjectKeySelector{IncludeAllKeys: ptr.To(false)}, "Invalid value: \"key: ' ', includeAllKeys: false\": source %s key must be defined when includeAllKeys is false"),
				Entry("when both set", &trustapi.SourceObjectKeySelector{Key: "ca.crt", IncludeAllKeys: ptr.To(true)}, "Invalid value: \"key: ca.crt, includeAllKeys: true\": source %s key cannot be defined when includeAllKeys is true"),
			)
		}

		Context("ConfigMap", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustapi.SourceObjectKeySelector) {
					bundle.Spec.Sources[0].ConfigMap = selector
				}
				field = "configMap"
			})

			sourceObjectAsserts()
		})

		Context("Secret", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustapi.SourceObjectKeySelector) {
					bundle.Spec.Sources[0].Secret = selector
				}
				field = "secret"
			})

			sourceObjectAsserts()
		})
	})

	Context("Target", func() {
		var (
			selectorAccessor func(*trustapi.TargetTemplate)
			field            string
		)

		It("should allow no targets", func() {
			Expect(cl.Create(ctx, bundle)).To(Succeed())
		})

		DescribeTable("should prevent annotations and labels with the trust manager prefixes",
			func(target trustapi.BundleTarget, wantErr bool) {
				bundle.Spec.Target = target
				if wantErr {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(
						SatisfyAny(
							ContainSubstring("Invalid value: \"trust.cert-manager.io/bundle\": trust.cert-manager.io/* labels are not allowed"),
							ContainSubstring("Invalid value: \"trust.cert-manager.io/hash\": trust.cert-manager.io/* annotations are not allowed"),
							ContainSubstring("Invalid value: \"trust-manager.io/bundle\": trust-manager.io/* labels are not allowed"),
							ContainSubstring("Invalid value: \"trust-manager.io/hash\": trust-manager.io/* annotations are not allowed"),
						),
					))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when trust-manager.io annotations are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Annotations: map[string]string{"trust-manager.io/hash": "test"}}}}, true),
			Entry("when trust.cert-manager.io annotations are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Annotations: map[string]string{"trust.cert-manager.io/hash": "test"}}}}, true),
			Entry("when trust-manager.io labels are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Labels: map[string]string{"trust-manager.io/bundle": "bundle"}}}}, true),
			Entry("when trust.cert-manager.io labels are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Labels: map[string]string{"trust.cert-manager.io/bundle": "bundle"}}}}, true),
			Entry("when non-reserved annotations are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Annotations: map[string]string{"not-trust-manager.io/hash": "test"}}}}, false),
			Entry("when non-reserved labels are used", trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{Key: "ca-bundle.crt", Metadata: &trustapi.TargetMetadata{Labels: map[string]string{"not-trust-manager.io/bundle": "bundle"}}}}, false),
		)

		type TargetKeySpec struct {
			ConfigMapKey string
			SecretKey    string
			JKSKey       string
			PKCS12Key    string
		}

		DescribeTable("should require additional format keys different from target keys",
			func(keySpec TargetKeySpec, wantErr bool) {
				target := trustapi.BundleTarget{}
				if keySpec.ConfigMapKey != "" {
					target.ConfigMap = &trustapi.TargetTemplate{Key: keySpec.ConfigMapKey}
				}
				if keySpec.SecretKey != "" {
					target.Secret = &trustapi.TargetTemplate{Key: keySpec.SecretKey}
				}
				if keySpec.JKSKey != "" {
					if target.AdditionalFormats == nil {
						target.AdditionalFormats = &trustapi.AdditionalFormats{}
					}
					target.AdditionalFormats.JKS = &trustapi.JKS{KeySelector: trustapi.KeySelector{Key: keySpec.JKSKey}}
				}
				if keySpec.PKCS12Key != "" {
					if target.AdditionalFormats == nil {
						target.AdditionalFormats = &trustapi.AdditionalFormats{}
					}
					target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{KeySelector: trustapi.KeySelector{Key: keySpec.PKCS12Key}}
				}
				bundle.Spec.Target = target

				if wantErr {
					expectedErr := "key must be unique across all target output keys"
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry(nil, TargetKeySpec{ConfigMapKey: "ca.crt"}, false),
			Entry(nil, TargetKeySpec{SecretKey: "ca.crt"}, false),
			Entry(nil, TargetKeySpec{ConfigMapKey: "ca.crt", SecretKey: "ca.crt"}, false),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s"}, false),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "j"}, false),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", PKCS12Key: "p"}, false),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "j", PKCS12Key: "p"}, false),

			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "c"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", PKCS12Key: "c"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "c", PKCS12Key: "p"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "j", PKCS12Key: "c"}, true),

			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "s"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", PKCS12Key: "s"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "s", PKCS12Key: "p"}, true),
			Entry(nil, TargetKeySpec{ConfigMapKey: "c", SecretKey: "s", JKSKey: "j", PKCS12Key: "s"}, true),
		)

		DescribeTable("should validate additional formats",
			func(formats *trustapi.AdditionalFormats, wantErr string) {
				bundle.Spec.Target.AdditionalFormats = formats
				if wantErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(wantErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when none set", &trustapi.AdditionalFormats{}, "spec.target.additionalFormats: Invalid value: at least one of the fields in [jks pkcs12] must be set"),
			Entry("when JKS key set", &trustapi.AdditionalFormats{JKS: &trustapi.JKS{KeySelector: trustapi.KeySelector{Key: "trust.jks"}}}, ""),
			Entry("when PKCS key set", &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{KeySelector: trustapi.KeySelector{Key: "trust.p12"}}}, ""),
			Entry("when both keys set, but different value", &trustapi.AdditionalFormats{JKS: &trustapi.JKS{KeySelector: trustapi.KeySelector{Key: "trust.jks"}}, PKCS12: &trustapi.PKCS12{KeySelector: trustapi.KeySelector{Key: "trust.p12"}}}, ""),
			Entry("when both keys set, same value", &trustapi.AdditionalFormats{JKS: &trustapi.JKS{KeySelector: trustapi.KeySelector{Key: "cacerts"}}, PKCS12: &trustapi.PKCS12{KeySelector: trustapi.KeySelector{Key: "cacerts"}}}, "Invalid value: \"cacerts\": key must be unique across all target output keys"),
		)

		targetObjectAsserts := func() {
			It("should require target key", func() {
				bundle.Spec.Target = trustapi.BundleTarget{}
				selectorAccessor(&trustapi.TargetTemplate{})
				expectedErr := "spec.target.%s.key: Required value"
				Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr, field)))
			})
		}

		Context("ConfigMap", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustapi.TargetTemplate) {
					bundle.Spec.Target.ConfigMap = selector
				}
				field = "configMap"
			})

			targetObjectAsserts()
		})

		Context("Secret", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustapi.TargetTemplate) {
					bundle.Spec.Target.Secret = selector
				}
				field = "secret"
			})

			targetObjectAsserts()
		})
	})
})
