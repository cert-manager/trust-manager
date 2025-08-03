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

	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	"github.com/cert-manager/trust-manager/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ClusterBundle Validation", func() {
	var (
		ctx    context.Context
		cl     client.Client
		bundle *trustmanagerapi.ClusterBundle
	)
	BeforeEach(func() {
		_, ctx = ktesting.NewTestContext(GinkgoT())

		var err error
		cl, err = client.New(env.Config, client.Options{
			Scheme: test.Scheme,
		})
		Expect(err).NotTo(HaveOccurred())

		bundle = &trustmanagerapi.ClusterBundle{}
		bundle.GenerateName = "validation-"
	})

	Context("Source item", func() {
		DescribeTable("should validate key",
			func(key string, matchErr string) {
				bundle.Spec.Sources = []trustmanagerapi.BundleSource{{
					Key: key,
					SourceReference: trustmanagerapi.SourceReference{
						Kind: trustmanagerapi.ConfigMapKind,
						Name: "ca",
					},
				}}
				if matchErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when unset", "", "spec.sources[0].key: Invalid value: \"\": spec.sources[0].key in body should be at least 1 chars long"),
			Entry("when given", "ca.crt", ""),
			Entry("when using simple wildcard to include some keys", "*.crt", ""),
			Entry("when using simple wildcard to include all keys", "*", ""),
			Entry("when using too advanced wildcards", "ca[0-9].crt", "spec.sources[0].key: Invalid value: \"ca[0-9].crt\": spec.sources[0].key in body should match '^[0-9A-Za-z_.\\-*]+$"),
		)

		DescribeTable("should validate source reference",
			func(sourceRef trustmanagerapi.SourceReference, matchErr string) {
				bundle.Spec.Sources = []trustmanagerapi.BundleSource{{
					Key:             "ca.crt",
					SourceReference: sourceRef,
				}}
				if matchErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when kind unset", trustmanagerapi.SourceReference{Name: "ca"}, "spec.sources[0].kind: Unsupported value: \"\": supported values: \"ConfigMap\", \"Secret\""),
			Entry("when kind ConfigMap", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Name: "ca"}, ""),
			Entry("when kind Secret", trustmanagerapi.SourceReference{Kind: trustmanagerapi.SecretKind, Name: "ca"}, ""),
			Entry("when kind unknown", trustmanagerapi.SourceReference{Kind: "OtherKind", Name: "ca"}, "spec.sources[0].kind: Unsupported value: \"OtherKind\": supported values: \"ConfigMap\", \"Secret\""),
			Entry("when no name nor selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind}, "spec.sources[0]: Invalid value: \"object\": exactly one of the following fields must be provided: [name, selector]"),
			Entry("when name set", trustmanagerapi.SourceReference{Name: "ca", Kind: trustmanagerapi.ConfigMapKind}, ""),
			Entry("when selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Selector: &metav1.LabelSelector{}}, ""),
			Entry("when name and selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Name: "ca", Selector: &metav1.LabelSelector{}}, "spec.sources[0]: Invalid value: \"object\": exactly one of the following fields must be provided: [name, selector]"),
		)
	})

	Context("Target", func() {
		var (
			selectorAccessor func(*trustmanagerapi.KeyValueTarget)
			field            string
		)

		BeforeEach(func() {
			bundle.Spec.Target = trustmanagerapi.BundleTarget{
				NamespaceSelector: &metav1.LabelSelector{},
			}
		})

		It("should require namespace selector", func() {
			bundle.Spec.Target.NamespaceSelector = nil
			bundle.Spec.Target.ConfigMap = &trustmanagerapi.KeyValueTarget{
				Data: []trustmanagerapi.TargetKeyValue{{
					Key: "ca-bundle.crt",
				}},
			}

			expectedErr := "spec.target.namespaceSelector: Required value"
			Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
		})

		It("should require a target if namespace selector set", func() {
			expectedErr := "spec.target: Invalid value: \"object\": any of the following fields must be provided: [configMap, secret]"
			Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(expectedErr)))
		})

		It("should allow both configmap and secret targets", func() {
			bundle.Spec.Target.ConfigMap = &trustmanagerapi.KeyValueTarget{
				Data: []trustmanagerapi.TargetKeyValue{{
					Key: "ca-bundle.crt",
				}},
			}
			bundle.Spec.Target.Secret = &trustmanagerapi.KeyValueTarget{
				Data: []trustmanagerapi.TargetKeyValue{{
					Key: "ca-bundle.crt",
				}},
			}
			Expect(cl.Create(ctx, bundle)).To(Succeed())
		})

		targetObjectAsserts := func() {
			DescribeTable("should validate key",
				func(key string, matchErr string) {
					selectorAccessor(&trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{
							Key: key,
						}},
					})
					if matchErr != "" {
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, field, field)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when unset", "", "spec.target.%s.data[0].key: Invalid value: \"\": spec.target.%s.data[0].key in body should be at least 1 chars long"),
				Entry("when given", "ca.crt", ""),
				Entry("when using wildcard", "*.crt", "spec.target.%s.data[0].key: Invalid value: \"*.crt\": spec.target.%s.data[0].key in body should match '^[0-9A-Za-z_.\\-]+$"),
			)

			It("should require unique keys", func() {
				selectorAccessor(&trustmanagerapi.KeyValueTarget{
					Data: []trustmanagerapi.TargetKeyValue{{
						Key: "foo",
					}, {
						Key: "foo",
					}},
				})
				matchErr := "spec.target.%s.data[1]: Duplicate value: map[string]interface {}{\"key\":\"foo\"}"
				Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, field)))

				selectorAccessor(&trustmanagerapi.KeyValueTarget{
					Data: []trustmanagerapi.TargetKeyValue{{
						Key: "foo",
					}, {
						Key: "bar",
					}},
				})
				Expect(cl.Create(ctx, bundle)).To(Succeed())
			})

			DescribeTable("should prevent metadata with forbidden prefixes",
				func(metadata *trustmanagerapi.TargetMetadata, wantErr bool) {
					selectorAccessor(&trustmanagerapi.KeyValueTarget{
						Metadata: metadata,
						Data: []trustmanagerapi.TargetKeyValue{{
							Key: "ca-bundle.crt",
						}},
					})
					if wantErr {
						var metadataField = "annotations"
						if metadata.Labels != nil {
							metadataField = "labels"
						}
						matchErr := "spec.target.%s.metadata.%s: Forbidden: must not use forbidden domains as prefixes (e.g., trust-manager.io)"
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, field, metadataField)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when trust-manager.io annotations are used", &trustmanagerapi.TargetMetadata{Annotations: map[string]string{"trust-manager.io/hash": "test"}}, true),
				Entry("when trust-manager.io labels are used", &trustmanagerapi.TargetMetadata{Labels: map[string]string{"trust-manager.io/bundle": "bundle"}}, true),
				Entry("when non-reserved annotations are used", &trustmanagerapi.TargetMetadata{Annotations: map[string]string{"not-trust-manager.io/hash": "test"}}, false),
				Entry("when non-reserved labels are used", &trustmanagerapi.TargetMetadata{Labels: map[string]string{"not-trust-manager.io/bundle": "bundle"}}, false),
			)

			DescribeTable("should validate format",
				func(format trustmanagerapi.BundleFormat, matchErr string) {
					selectorAccessor(&trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{
							Key:    "ca-bundle",
							Format: format,
						}},
					})
					if matchErr != "" {
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, field)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when unset", trustmanagerapi.BundleFormat(""), ""),
				Entry("when PEM", trustmanagerapi.BundleFormatPEM, ""),
				Entry("when PKCS12", trustmanagerapi.BundleFormatPKCS12, ""),
				Entry("when invalid case", trustmanagerapi.BundleFormat("PeM"), "spec.target.%s.data[0].format: Unsupported value: \"PeM\": supported values: \"PEM\", \"PKCS12\""),
				Entry("when invalid case", trustmanagerapi.BundleFormat("pem"), "spec.target.%s.data[0].format: Unsupported value: \"pem\": supported values: \"PEM\", \"PKCS12\""),
				Entry("when unknown", trustmanagerapi.BundleFormat("JKS"), "spec.target.%s.data[0].format: Unsupported value: \"JKS\": supported values: \"PEM\", \"PKCS12\""),
			)

			var pkcs12Field string
			var pkcs12 trustmanagerapi.PKCS12

			pkcs12Asserts := func() {
				DescribeTable("should validate fields reserved for PCKS12 format",
					func(format trustmanagerapi.BundleFormat, wantErr bool) {
						targetKeyValue := trustmanagerapi.TargetKeyValue{
							Key:    "ca-bundle",
							Format: format,
							PKCS12: pkcs12,
						}
						selectorAccessor(&trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{targetKeyValue},
						})

						if wantErr {
							matchErr := "spec.target.%s.data[0].%s: Forbidden: may only be set when format is 'PKCS12'"
							Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, field, pkcs12Field)))
						} else {
							Expect(cl.Create(ctx, bundle)).To(Succeed())
						}
					},
					Entry("reject it when format is empty", trustmanagerapi.BundleFormat(""), true),
					Entry("reject it when format is PEM", trustmanagerapi.BundleFormatPEM, true),
					Entry("accept it when format is PKCS12", trustmanagerapi.BundleFormatPKCS12, false),
				)
			}

			Context("Password", func() {
				BeforeEach(func() {
					pkcs12Field = "password"
					pkcs12 = trustmanagerapi.PKCS12{Password: ptr.To("my-password")}
				})

				pkcs12Asserts()
			})

			Context("Profile", func() {
				BeforeEach(func() {
					pkcs12Field = "profile"
					pkcs12 = trustmanagerapi.PKCS12{Profile: trustmanagerapi.Modern2023PKCS12Profile}
				})

				pkcs12Asserts()
			})
		}

		Context("ConfigMap", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustmanagerapi.KeyValueTarget) {
					bundle.Spec.Target.ConfigMap = selector
				}
				field = "configMap"
			})

			targetObjectAsserts()
		})

		Context("Secret", func() {
			BeforeEach(func() {
				selectorAccessor = func(selector *trustmanagerapi.KeyValueTarget) {
					bundle.Spec.Target.Secret = selector
				}
				field = "secret"
			})

			targetObjectAsserts()
		})
	})
})
