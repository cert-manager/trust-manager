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
	"strings"

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

	Context("Source reference", func() {
		DescribeTable("should validate key",
			func(key string, matchErr string) {
				bundle.Spec.SourceRefs = []trustmanagerapi.BundleSourceRef{{
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
			Entry("when unset", "", "spec.sourceRefs[0].key: Required value"),
			Entry("when given", "ca.crt", ""),
			Entry("when using simple wildcard to include some keys", "*.crt", ""),
			Entry("when using simple wildcard to include all keys", "*", ""),
			Entry("when using too advanced wildcards", "ca[0-9].crt", "spec.sourceRefs[0].key: Invalid value: \"ca[0-9].crt\": spec.sourceRefs[0].key in body should match '^[0-9A-Za-z_.\\-*]+$"),
		)

		DescribeTable("should validate refs",
			func(sourceRef trustmanagerapi.SourceReference, matchErr string) {
				bundle.Spec.SourceRefs = []trustmanagerapi.BundleSourceRef{{
					Key:             "ca.crt",
					SourceReference: sourceRef,
				}}
				if matchErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("when kind unset", trustmanagerapi.SourceReference{Name: "ca"}, "spec.sourceRefs[0].kind: Required value"),
			Entry("when kind ConfigMap", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Name: "ca"}, ""),
			Entry("when kind Secret", trustmanagerapi.SourceReference{Kind: trustmanagerapi.SecretKind, Name: "ca"}, ""),
			Entry("when kind unknown", trustmanagerapi.SourceReference{Kind: "OtherKind", Name: "ca"}, "spec.sourceRefs[0].kind: Unsupported value: \"OtherKind\": supported values: \"ConfigMap\", \"Secret\""),
			Entry("when no name nor selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind}, "spec.sourceRefs[0]: Invalid value: exactly one of the fields in [name selector] must be set"),
			Entry("when name set", trustmanagerapi.SourceReference{Name: "ca", Kind: trustmanagerapi.ConfigMapKind}, ""),
			Entry("when selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Selector: &metav1.LabelSelector{}}, ""),
			Entry("when invalid selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"@@@@": "test"}}}, "spec.sourceRefs[0].selector.matchLabels: Invalid value: \"@@@@\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
			Entry("when name and selector set", trustmanagerapi.SourceReference{Kind: trustmanagerapi.ConfigMapKind, Name: "ca", Selector: &metav1.LabelSelector{}}, "spec.sourceRefs[0]: Invalid value: exactly one of the fields in [name selector] must be set"),
		)
	})

	Context("Target", func() {
		var (
			targetField string
			setTarget   func(*trustmanagerapi.KeyValueTarget)
		)

		BeforeEach(func() {
			bundle.Spec.Target = trustmanagerapi.BundleTarget{
				NamespaceSelector: &metav1.LabelSelector{},
			}
		})

		DescribeTable("should validate namespace selector",
			func(selector *metav1.LabelSelector, matchErr string) {
				bundle.Spec.Target.NamespaceSelector = selector
				bundle.Spec.Target.ConfigMap = &trustmanagerapi.KeyValueTarget{
					Data: []trustmanagerapi.TargetKeyValue{{
						Key: "ca-bundle.crt",
					}},
				}

				if matchErr != "" {
					Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr)))
				} else {
					Expect(cl.Create(ctx, bundle)).To(Succeed())
				}
			},
			Entry("reject if unset", nil, "spec.target.namespaceSelector: Required value"),
			Entry("reject invalid", &metav1.LabelSelector{MatchLabels: map[string]string{"@@@@": "test"}}, "spec.target.namespaceSelector.matchLabels: Invalid value: \"@@@@\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
			Entry("accept valid", &metav1.LabelSelector{MatchLabels: map[string]string{"foo": "bar"}}, ""),
		)

		It("should require a target if namespace selector set", func() {
			expectedErr := "spec.target: Invalid value: at least one of the fields in [configMap secret] must be set"
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
					setTarget(&trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{
							Key: key,
						}},
					})
					if matchErr != "" {
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField)))
					} else {
						Expect(cl.Create(ctx, bundle)).To(Succeed())
					}
				},
				Entry("when unset", "", "spec.target.%s.data[0].key: Required value"),
				Entry("when given", "ca.crt", ""),
				Entry("when using wildcard", "*.crt", "spec.target.%[1]s.data[0].key: Invalid value: \"*.crt\": spec.target.%[1]s.data[0].key in body should match '^[0-9A-Za-z_.\\-]+$"),
			)

			It("should require unique keys", func() {
				setTarget(&trustmanagerapi.KeyValueTarget{
					Data: []trustmanagerapi.TargetKeyValue{{
						Key: "foo",
					}, {
						Key: "foo",
					}},
				})
				matchErr := "spec.target.%s.data[1]: Duplicate value: {\"key\":\"foo\"}"
				Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField)))

				setTarget(&trustmanagerapi.KeyValueTarget{
					Data: []trustmanagerapi.TargetKeyValue{{
						Key: "foo",
					}, {
						Key: "bar",
					}},
				})
				Expect(cl.Create(ctx, bundle)).To(Succeed())
			})

			Context("Metadata", func() {
				var (
					metadataField      string
					metadata           *trustmanagerapi.TargetMetadata
					setMetadata        func(map[string]string)
					expValueValidation bool
				)

				BeforeEach(func() {
					metadata = &trustmanagerapi.TargetMetadata{}
					setTarget(&trustmanagerapi.KeyValueTarget{
						Metadata: metadata,
						Data: []trustmanagerapi.TargetKeyValue{{
							Key: "ca-bundle.crt",
						}},
					})
				})

				metadataAsserts := func() {
					DescribeTable("should validate keys",
						func(m map[string]string, matchErr string) {
							setMetadata(m)

							if matchErr != "" {
								Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField, metadataField)))
							} else {
								Expect(cl.Create(ctx, bundle)).To(Succeed())
							}
						},
						Entry("reject trust-manager.io prefix", map[string]string{"trust-manager.io/hash": "test"}, "spec.target.%s.metadata.%s: Forbidden: must not use forbidden domains as prefixes (e.g., trust-manager.io)"),
						Entry("accept non-reserved prefix", map[string]string{"not-trust-manager.io/hash": "test"}, ""),
						Entry("reject invalid characters", map[string]string{"@@@@": "test"}, "spec.target.%s.metadata.%s: Invalid value: \"@@@@\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]"),
						Entry("reject too long name", map[string]string{strings.Repeat("a", 64): "test"}, "spec.target.%s.metadata.%s: Invalid value: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\": name part must be no more than 63 bytes"),
						Entry("accept long prefixes", map[string]string{strings.Repeat("a", 64) + "/foo": "test"}, ""),
					)

					DescribeTable("should validate values",
						func(m map[string]string, matchErr string) {
							setMetadata(m)

							if expValueValidation && matchErr != "" {
								Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField, metadataField)))
							} else {
								Expect(cl.Create(ctx, bundle)).To(Succeed())
							}
						},
						Entry("reject invalid characters", map[string]string{"foo": "@@@@@"}, "spec.target.%s.metadata.%s: Invalid value: \"@@@@@\": a valid label must be an empty string or consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyValue',  or 'my_value',  or '12345', regex used for validation is '(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"),
						Entry("reject too long", map[string]string{"foo": strings.Repeat("a", 64)}, "spec.target.%s.metadata.%s: Invalid value: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\": must be no more than 63 bytes"),
					)
				}

				Context("Annotations", func() {
					BeforeEach(func() {
						metadataField = "annotations"
						setMetadata = func(m map[string]string) {
							metadata.Annotations = m
						}
						expValueValidation = false
					})

					metadataAsserts()
				})

				Context("Labels", func() {
					BeforeEach(func() {
						metadataField = "labels"
						setMetadata = func(m map[string]string) {
							metadata.Labels = m
						}
						expValueValidation = true
					})

					metadataAsserts()
				})
			})

			DescribeTable("should validate format",
				func(format trustmanagerapi.BundleFormat, matchErr string) {
					setTarget(&trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{
							Key:    "ca-bundle",
							Format: format,
						}},
					})
					if matchErr != "" {
						Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField)))
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

			var (
				pkcs12Field string
				pkcs12      trustmanagerapi.PKCS12
			)

			pkcs12Asserts := func() {
				DescribeTable("should validate fields reserved for PCKS12 format",
					func(format trustmanagerapi.BundleFormat, wantErr bool) {
						targetKeyValue := trustmanagerapi.TargetKeyValue{
							Key:    "ca-bundle",
							Format: format,
							PKCS12: pkcs12,
						}
						setTarget(&trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{targetKeyValue},
						})

						if wantErr {
							matchErr := "spec.target.%s.data[0].%s: Forbidden: may only be set when format is 'PKCS12'"
							Expect(cl.Create(ctx, bundle)).Should(MatchError(ContainSubstring(matchErr, targetField, pkcs12Field)))
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
				targetField = "configMap"
				setTarget = func(selector *trustmanagerapi.KeyValueTarget) {
					bundle.Spec.Target.ConfigMap = selector
				}
			})

			targetObjectAsserts()
		})

		Context("Secret", func() {
			BeforeEach(func() {
				targetField = "secret"
				setTarget = func(selector *trustmanagerapi.KeyValueTarget) {
					bundle.Spec.Target.Secret = selector
				}
			})

			targetObjectAsserts()
		})
	})
})
