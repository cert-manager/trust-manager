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
	"testing"

	fuzz "github.com/google/gofuzz"
	"k8s.io/apimachinery/pkg/api/apitesting/fuzzer"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"

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
		spokeBundleTargetFuzzer,
		hubBundleTargetFuzzer,
	}
}

func spokeBundleTargetFuzzer(obj *BundleTarget, c fuzz.Continue) {
	c.FuzzNoCustom(obj)

	if obj.Secret == nil && obj.ConfigMap == nil {
		obj.AdditionalFormats = nil
	}
	if obj.AdditionalFormats != nil {
		if obj.AdditionalFormats.PKCS12 != nil && obj.AdditionalFormats.PKCS12.Profile == "" {
			obj.AdditionalFormats.PKCS12.Profile = LegacyRC2PKCS12Profile
		}
		if obj.AdditionalFormats.JKS == nil && obj.AdditionalFormats.PKCS12 == nil {
			obj.AdditionalFormats = nil
		}
	}
}

func hubBundleTargetFuzzer(obj *trustv1alpha2.BundleTarget, c fuzz.Continue) {
	c.FuzzNoCustom(obj)

	normalizeTarget := func(target trustv1alpha2.KeyValueTarget) trustv1alpha2.KeyValueTarget {
		var pemFound bool
		var tm trustv1alpha2.KeyValueTarget
		for _, tkv := range target {
			if tkv.Key == "" {
				// Key is a mandatory field
				continue
			}
			switch {
			case tkv.JKS != nil:
				tkv.Format = trustv1alpha2.BundleFormatJKS
				tkv.PKCS12 = nil
			case tkv.PKCS12 != nil:
				tkv.Format = trustv1alpha2.BundleFormatPKCS12
				tkv.JKS = nil
			default:
				tkv.Format = ""
				pemFound = true
			}
			tm = append(tm, tkv)
		}
		if !pemFound {
			// No default format (PEM) keys found, which is not supported by v1alpha1 targets
			return nil
		}
		return tm
	}

	obj.ConfigMap = normalizeTarget(obj.ConfigMap)
	obj.Secret = normalizeTarget(obj.Secret)
}
