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
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
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
						{InLine: ptr.To(dummy.TestCertificate1)},
						{InLine: ptr.To(dummy.TestCertificate2)},
					},
				},
			},
			exp: trustmanagerapi.ClusterBundle{
				Spec: trustmanagerapi.BundleSpec{
					InLineCAs: ptr.To(dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2)),
				},
			},
			// This asserts that the conversion is NOT round-trippable, but equivalent
			expSrc: Bundle{
				Spec: BundleSpec{
					Sources: []BundleSource{
						{InLine: ptr.To(dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2))},
					},
				},
			},
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
		if bs.InLine != nil {
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
	if obj.IncludeAllKeys {
		obj.Key = ""
	} else if obj.Key == "" {
		obj.IncludeAllKeys = true
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
