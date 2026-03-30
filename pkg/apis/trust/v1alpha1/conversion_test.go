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

package v1alpha1

import (
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/randfill"

	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	utilconversion "github.com/cert-manager/trust-manager/pkg/util/conversion"
	"github.com/cert-manager/trust-manager/test/dummy"
)

// TestBundle_Conversion is for additional/special testcases not fully covered by TestFuzzyConversion below.
func TestBundle_Conversion(t *testing.T) {
	tests := map[string]struct {
		src    Bundle
		exp    trustmanagerapi.ClusterBundle
		expSrc Bundle
	}{
		"multiple inline Bundle sources should be concatenated in ClusterBundle inLineCAs": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{InLine: dummy.TestCertificate1},
						{InLine: dummy.TestCertificate2},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					InLineCAs: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
				},
			},
			// This asserts that the conversion is NOT round-trippable, but equivalent
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{InLine: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2)},
					},
				},
			},
		},
		"ConfigMap source with key should convert to ConfigMap kind sourceRef": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Name: "my-configmap",
							Key:  "ca.crt",
						}},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-configmap",
							},
							Key: "ca.crt",
						},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Name: "my-configmap",
							Key:  "ca.crt",
						}},
					},
				},
			},
		},
		"Secret source with key should convert to Secret kind sourceRef": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{Secret: &SourceObjectKeySelector{
							Name: "my-secret",
							Key:  "tls.crt",
						}},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.SecretKind,
								Name: "my-secret",
							},
							Key: "tls.crt",
						},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{Secret: &SourceObjectKeySelector{
							Name: "my-secret",
							Key:  "tls.crt",
						}},
					},
				},
			},
		},
		"ConfigMap source with includeAllKeys should convert to wildcard key": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Name:           "my-configmap",
							IncludeAllKeys: ptr.To(true),
						}},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-configmap",
							},
							Key: "*",
						},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Name:           "my-configmap",
							IncludeAllKeys: ptr.To(true),
						}},
					},
				},
			},
		},
		"ConfigMap source with label selector should preserve selector": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "trust"},
							},
							Key: "ca-bundle.pem",
						}},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Selector: &metav1.LabelSelector{
									MatchLabels: map[string]string{"app": "trust"},
								},
							},
							Key: "ca-bundle.pem",
						},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{
							Selector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "trust"},
							},
							Key: "ca-bundle.pem",
						}},
					},
				},
			},
		},
		"useDefaultCAs true should convert to DefaultCAs with System provider": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{UseDefaultCAs: ptr.To(true)},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					DefaultCAs: trustmanagerapi.DefaultCAsSource{
						Provider: trustmanagerapi.DefaultCAsProviderSystem,
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{UseDefaultCAs: ptr.To(true)},
					},
				},
			},
		},
		"useDefaultCAs false should convert to DefaultCAs with Disabled provider": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{UseDefaultCAs: ptr.To(false)},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					DefaultCAs: trustmanagerapi.DefaultCAsSource{
						Provider: trustmanagerapi.DefaultCAsProviderDisabled,
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{UseDefaultCAs: ptr.To(false)},
					},
				},
			},
		},
		"JKS additional format should convert to PKCS12 format with JKS annotation": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							JKS: &JKS{
								KeySelector: KeySelector{Key: "trust-bundle.jks"},
								Password:    "changeit",
							},
						},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationKeyJKSKey: "trust-bundle.jks",
					},
				},
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						ConfigMap: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "trust-bundle.pem"},
								{
									Key:    "trust-bundle.jks",
									Format: trustmanagerapi.BundleFormatPKCS12,
									PKCS12: trustmanagerapi.PKCS12{
										Password: ptr.To("changeit"),
									},
								},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							JKS: &JKS{
								KeySelector: KeySelector{Key: "trust-bundle.jks"},
								Password:    "changeit",
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"PKCS12 additional format should convert with profile defaulting to LegacyRC2": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "trust-bundle.p12"},
								Password:    ptr.To("secret"),
							},
						},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						ConfigMap: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "trust-bundle.pem"},
								{
									Key:    "trust-bundle.p12",
									Format: trustmanagerapi.BundleFormatPKCS12,
									PKCS12: trustmanagerapi.PKCS12{
										Password: ptr.To("secret"),
										Profile:  trustmanagerapi.LegacyRC2PKCS12Profile,
									},
								},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "trust-bundle.p12"},
								Password:    ptr.To("secret"),
								Profile:     LegacyRC2PKCS12Profile,
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"PKCS12 additional format with explicit Modern2023 profile should preserve profile": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "trust-bundle.p12"},
								Password:    ptr.To(""),
								Profile:     Modern2023PKCS12Profile,
							},
						},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						ConfigMap: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "trust-bundle.pem"},
								{
									Key:    "trust-bundle.p12",
									Format: trustmanagerapi.BundleFormatPKCS12,
									PKCS12: trustmanagerapi.PKCS12{
										Password: ptr.To(""),
										Profile:  trustmanagerapi.Modern2023PKCS12Profile,
									},
								},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "trust-bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "trust-bundle.p12"},
								Password:    ptr.To(""),
								Profile:     Modern2023PKCS12Profile,
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"both JKS and PKCS12 additional formats should convert correctly": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{Secret: &SourceObjectKeySelector{Name: "my-secret", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						Secret: &TargetTemplate{Key: "bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							JKS: &JKS{
								KeySelector: KeySelector{Key: "bundle.jks"},
								Password:    "changeit",
							},
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "bundle.p12"},
								Password:    ptr.To("p12pass"),
								Profile:     LegacyDESPKCS12Profile,
							},
						},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationKeyJKSKey: "bundle.jks",
					},
				},
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.SecretKind,
								Name: "my-secret",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						Secret: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "bundle.pem"},
								{
									Key:    "bundle.jks",
									Format: trustmanagerapi.BundleFormatPKCS12,
									PKCS12: trustmanagerapi.PKCS12{
										Password: ptr.To("changeit"),
									},
								},
								{
									Key:    "bundle.p12",
									Format: trustmanagerapi.BundleFormatPKCS12,
									PKCS12: trustmanagerapi.PKCS12{
										Password: ptr.To("p12pass"),
										Profile:  trustmanagerapi.LegacyDESPKCS12Profile,
									},
								},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{Secret: &SourceObjectKeySelector{Name: "my-secret", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						Secret: &TargetTemplate{Key: "bundle.pem"},
						AdditionalFormats: &AdditionalFormats{
							JKS: &JKS{
								KeySelector: KeySelector{Key: "bundle.jks"},
								Password:    "changeit",
							},
							PKCS12: &PKCS12{
								KeySelector: KeySelector{Key: "bundle.p12"},
								Password:    ptr.To("p12pass"),
								Profile:     LegacyDESPKCS12Profile,
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"nil namespaceSelector should default to empty LabelSelector in ClusterBundle": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "bundle.pem"},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						ConfigMap: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "bundle.pem"},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{Key: "bundle.pem"},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"target metadata should be preserved during conversion": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{
							Key: "bundle.pem",
							Metadata: TargetMetadata{
								Labels:      map[string]string{"app": "trust"},
								Annotations: map[string]string{"note": "managed"},
							},
						},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
					Target: trustmanagerapi.BundleTarget{
						ConfigMap: &trustmanagerapi.KeyValueTarget{
							Data: []trustmanagerapi.TargetKeyValue{
								{Key: "bundle.pem"},
							},
							Metadata: trustmanagerapi.TargetMetadata{
								Labels:      map[string]string{"app": "trust"},
								Annotations: map[string]string{"note": "managed"},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
					Target: BundleTarget{
						ConfigMap: &TargetTemplate{
							Key: "bundle.pem",
							Metadata: TargetMetadata{
								Labels:      map[string]string{"app": "trust"},
								Annotations: map[string]string{"note": "managed"},
							},
						},
						NamespaceSelector: &metav1.LabelSelector{},
					},
				},
			},
		},
		"mixed source types should convert to appropriate ClusterBundle fields": {
			src: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "cm-1", Key: "ca.crt"}},
						{Secret: &SourceObjectKeySelector{Name: "sec-1", Key: "tls.crt"}},
						{InLine: dummy.TestCertificate1},
						{UseDefaultCAs: ptr.To(true)},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "cm-1",
							},
							Key: "ca.crt",
						},
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.SecretKind,
								Name: "sec-1",
							},
							Key: "tls.crt",
						},
					},
					InLineCAs: dummy.TestCertificate1,
					DefaultCAs: trustmanagerapi.DefaultCAsSource{
						Provider: trustmanagerapi.DefaultCAsProviderSystem,
					},
				},
			},
			// InLine and UseDefaultCAs are promoted to spec-level fields, not sourceRefs.
			// On round-trip they come back as separate sources at the end of the list.
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "cm-1", Key: "ca.crt"}},
						{Secret: &SourceObjectKeySelector{Name: "sec-1", Key: "tls.crt"}},
						{InLine: dummy.TestCertificate1},
						{UseDefaultCAs: ptr.To(true)},
					},
				},
			},
		},
		"ObjectMeta should be preserved during conversion": {
			src: Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-bundle",
					Labels:      map[string]string{"app": "trust"},
					Annotations: map[string]string{"note": "test"},
				},
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-bundle",
					Labels:      map[string]string{"app": "trust"},
					Annotations: map[string]string{"note": "test"},
				},
				Spec: trustmanagerapi.BundleSpec{
					SourceRefs: []trustmanagerapi.BundleSourceRef{
						{
							SourceReference: trustmanagerapi.SourceReference{
								Kind: trustmanagerapi.ConfigMapKind,
								Name: "my-cm",
							},
							Key: "ca.crt",
						},
					},
				},
			},
			expSrc: Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-bundle",
					Labels:      map[string]string{"app": "trust"},
					Annotations: map[string]string{"note": "test"},
				},
				Spec: BundleSpec{
					Sources: []BundleSource{
						{ConfigMap: &SourceObjectKeySelector{Name: "my-cm", Key: "ca.crt"}},
					},
				},
			},
		},
		"empty spec should convert without error": {
			src:    Bundle{},
			exp:    trustmanagerapi.ClusterBundle{},
			expSrc: Bundle{},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dst := trustmanagerapi.ClusterBundle{}
			err := tt.src.ConvertTo(&dst)
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, dst)

			src := Bundle{}
			err = src.ConvertFrom(&dst)
			assert.NoError(t, err)
			assert.Equal(t, tt.expSrc, src)
		})
	}
}

// fakeHub is a test type that implements the conversion.Hub interface but is not a ClusterBundle.
type fakeHub struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`
}

func (f *fakeHub) Hub()                                                 {}
func (f *fakeHub) DeepCopyObject() runtime.Object                       { return f }
func (f *fakeHub) GetObjectKind() schema.ObjectKind                     { return &f.TypeMeta }

func TestBundle_ConvertTo_WrongType(t *testing.T) {
	src := &Bundle{}
	err := src.ConvertTo(&fakeHub{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected a ClusterBundle")
}

func TestBundle_ConvertFrom_WrongType(t *testing.T) {
	dst := &Bundle{}
	err := dst.ConvertFrom(&fakeHub{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected a ClusterBundle")
}

func TestFuzzyConversion(t *testing.T) {
	t.Run("for Bundle", utilconversion.FuzzTestFunc(utilconversion.FuzzTestFuncInput{
		Hub:         &trustmanagerapi.ClusterBundle{},
		Spoke:       &Bundle{},
		FuzzerFuncs: []fuzzer.FuzzerFuncs{fuzzFuncs},
	}))
}

func fuzzFuncs(_ runtimeserializer.CodecFactory) []any {
	return []any{
		spokeBundleSpecFuzzer,
		spokeSourceObjectKeySelectorFuzzer,
		spokeBundleTargetFuzzer,
		hubBundleSourceRefFuzzer,
		hubDefaultCAsFuzzer,
		hubBundleTargetFuzzer,
	}
}

func spokeBundleSpecFuzzer(obj *BundleSpec, c randfill.Continue) {
	c.FillNoCustom(obj)

	// We require exactly one source type for each item
	obj.Sources = slices.DeleteFunc(obj.Sources, func(bs BundleSource) bool {
		sourceCount := 0
		if bs.ConfigMap != nil {
			sourceCount++
		}
		if bs.Secret != nil {
			sourceCount++
		}
		if bs.InLine != "" {
			sourceCount++
		}
		if bs.UseDefaultCAs != nil {
			sourceCount++
		}
		return sourceCount != 1
	})
}

func spokeSourceObjectKeySelectorFuzzer(obj *SourceObjectKeySelector, c randfill.Continue) {
	c.FillNoCustom(obj)

	// Key and IncludeAllKeys cannot be used at the same time
	switch {
	case ptr.Deref(obj.IncludeAllKeys, false):
		obj.Key = ""
	case obj.Key == "":
		obj.IncludeAllKeys = ptr.To(true)
	default:
		obj.IncludeAllKeys = nil
	}
}

func spokeBundleTargetFuzzer(obj *BundleTarget, c randfill.Continue) {
	c.FillNoCustom(obj)

	if (obj.Secret == nil || obj.Secret.Key == "") && (obj.ConfigMap == nil || obj.ConfigMap.Key == "") {
		// Key is a mandatory field
		obj.AdditionalFormats = nil
	}
	if obj.AdditionalFormats != nil {
		if obj.AdditionalFormats.PKCS12 != nil && obj.AdditionalFormats.PKCS12.Profile == "" {
			obj.AdditionalFormats.PKCS12.Profile = LegacyRC2PKCS12Profile
		}
		if obj.AdditionalFormats.PKCS12 != nil && obj.AdditionalFormats.PKCS12.Key == "" {
			// Key is a mandatory field
			obj.AdditionalFormats.PKCS12 = nil
		}

		if obj.AdditionalFormats.JKS != nil && obj.AdditionalFormats.JKS.Key == "" {
			// Key is a mandatory field
			obj.AdditionalFormats.JKS = nil
		}

		if obj.AdditionalFormats.PKCS12 == nil && obj.AdditionalFormats.JKS == nil {
			obj.AdditionalFormats = nil
		}
	}
}

func hubBundleSourceRefFuzzer(obj *trustmanagerapi.BundleSourceRef, c randfill.Continue) {
	c.FillNoCustom(obj)

	// We only allow known kinds, so must normalize the source kind
	kindSet := []string{trustmanagerapi.ConfigMapKind, trustmanagerapi.SecretKind}
	obj.Kind = kindSet[rand.Intn(len(kindSet))] //nolint:gosec
}

func hubDefaultCAsFuzzer(obj *trustmanagerapi.DefaultCAsSource, c randfill.Continue) {
	c.FillNoCustom(obj)

	// We only allow known providers, so must normalize the provider
	providerSet := []string{trustmanagerapi.DefaultCAsProviderDisabled, trustmanagerapi.DefaultCAsProviderSystem}
	obj.Provider = providerSet[rand.Intn(len(providerSet))] //nolint:gosec
}

func hubBundleTargetFuzzer(obj *trustmanagerapi.BundleTarget, c randfill.Continue) {
	c.FillNoCustom(obj)

	normalizeTarget := func(target *trustmanagerapi.KeyValueTarget) *trustmanagerapi.KeyValueTarget {
		if target == nil {
			return nil
		}

		target.Data = slices.DeleteFunc(target.Data, func(tkv trustmanagerapi.TargetKeyValue) bool {
			if tkv.Key == "" {
				// Key is a mandatory field
				return true
			}
			return false
		})

		var pemFound bool
		for i, tkv := range target.Data {

			switch {
			case tkv.Password != nil:
				tkv.Format = trustmanagerapi.BundleFormatPKCS12
			default:
				tkv.Format = ""
				tkv.Profile = ""

				pemFound = true
			}
			target.Data[i] = tkv
		}

		if !pemFound {
			// No default format (PEM) keys found, which is not supported by v1alpha1 targets
			return nil
		}
		return target
	}

	obj.ConfigMap = normalizeTarget(obj.ConfigMap)
	obj.Secret = normalizeTarget(obj.Secret)
}
