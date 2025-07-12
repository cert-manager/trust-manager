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

	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/randfill"

	trustv1alpha2 "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	utilconversion "github.com/cert-manager/trust-manager/pkg/util/conversion"
)

func TestFuzzyConversion(t *testing.T) {
	t.Run("for Bundle", utilconversion.FuzzTestFunc(utilconversion.FuzzTestFuncInput{
		Hub:         &trustv1alpha2.ClusterBundle{},
		Spoke:       &Bundle{},
		FuzzerFuncs: []fuzzer.FuzzerFuncs{fuzzFuncs},
	}))
}

func fuzzFuncs(_ runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		spokeBundleSpecFuzzer,
		spokeBundleTargetFuzzer,
		hubBundleSourceFuzzer,
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

func hubBundleSourceFuzzer(obj *trustv1alpha2.BundleSource, c randfill.Continue) {
	c.FillNoCustom(obj)

	// We only allow known kinds, so must normalize the source kind
	kindSet := []string{trustv1alpha2.ConfigMapKind, trustv1alpha2.SecretKind}
	obj.Kind = kindSet[rand.Intn(len(kindSet))] //nolint:gosec
}

func hubBundleTargetFuzzer(obj *trustv1alpha2.BundleTarget, c randfill.Continue) {
	c.FillNoCustom(obj)

	normalizeTarget := func(target *trustv1alpha2.KeyValueTarget) *trustv1alpha2.KeyValueTarget {
		if target == nil {
			return nil
		}

		target.Data = slices.DeleteFunc(target.Data, func(tkv trustv1alpha2.TargetKeyValue) bool {
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
				tkv.Format = trustv1alpha2.BundleFormatPKCS12
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
