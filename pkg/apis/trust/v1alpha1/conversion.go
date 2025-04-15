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
	"slices"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachineryconversion "k8s.io/apimachinery/pkg/conversion"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	trustv1alpha2 "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
)

func (src *Bundle) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*trustv1alpha2.ClusterBundle)
	dst.ObjectMeta = src.ObjectMeta
	if err := Convert_v1alpha1_BundleSpec_To_v1alpha2_BundleSpec(&src.Spec, &dst.Spec, nil); err != nil {
		return err
	}
	if err := Convert_v1alpha1_BundleStatus_To_v1alpha2_BundleStatus(&src.Status, &dst.Status, nil); err != nil {
		return err
	}
	return nil
}

func Convert_v1alpha1_BundleTarget_To_v1alpha2_BundleTarget(in *BundleTarget, out *trustv1alpha2.BundleTarget, scope apimachineryconversion.Scope) error {
	if in.ConfigMap != nil {
		out.ConfigMap = append(out.ConfigMap, trustv1alpha2.TargetKeyValue{Key: in.ConfigMap.Key})
	}
	if in.Secret != nil {
		out.Secret = append(out.Secret, trustv1alpha2.TargetKeyValue{Key: in.Secret.Key})
	}

	if in.AdditionalFormats != nil {
		appendTargetKV := func(tkv trustv1alpha2.TargetKeyValue) {
			if out.ConfigMap != nil {
				out.ConfigMap = append(out.ConfigMap, tkv)
			}
			if out.Secret != nil {
				out.Secret = append(out.Secret, tkv)
			}
		}

		if in.AdditionalFormats.JKS != nil {
			targetKV := trustv1alpha2.TargetKeyValue{
				Key:    in.AdditionalFormats.JKS.Key,
				Format: trustv1alpha2.BundleFormatJKS,
				JKS:    &trustv1alpha2.JKS{},
			}
			if err := Convert_v1alpha1_JKS_To_v1alpha2_JKS(in.AdditionalFormats.JKS, targetKV.JKS, scope); err != nil {
				return err
			}
			appendTargetKV(targetKV)
		}
		if in.AdditionalFormats.PKCS12 != nil {
			targetKV := trustv1alpha2.TargetKeyValue{
				Key:    in.AdditionalFormats.PKCS12.Key,
				Format: trustv1alpha2.BundleFormatPKCS12,
				PKCS12: &trustv1alpha2.PKCS12{},
			}
			if err := Convert_v1alpha1_PKCS12_To_v1alpha2_PKCS12(in.AdditionalFormats.PKCS12, targetKV.PKCS12, scope); err != nil {
				return err
			}
			appendTargetKV(targetKV)
		}
	}

	out.NamespaceSelector = in.NamespaceSelector
	if out.NamespaceSelector == nil {
		// NamespaceSelector is required in v1alpha2
		out.NamespaceSelector = &metav1.LabelSelector{}
	}
	return nil
}

func Convert_v1alpha1_JKS_To_v1alpha2_JKS(in *JKS, out *trustv1alpha2.JKS, _ apimachineryconversion.Scope) error {
	out.Password = in.Password
	return nil
}

func Convert_v1alpha1_PKCS12_To_v1alpha2_PKCS12(in *PKCS12, out *trustv1alpha2.PKCS12, _ apimachineryconversion.Scope) error {
	out.Password = in.Password
	out.Profile = trustv1alpha2.PKCS12Profile(in.Profile)
	if out.Profile == "" {
		// Default profile changed from LegacyRC2 to LegacyDES in v1alpha2
		out.Profile = trustv1alpha2.LegacyRC2PKCS12Profile
	}
	return nil
}

func (dst *Bundle) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*trustv1alpha2.ClusterBundle)
	dst.ObjectMeta = src.ObjectMeta
	if err := Convert_v1alpha2_BundleSpec_To_v1alpha1_BundleSpec(&src.Spec, &dst.Spec, nil); err != nil {
		return err
	}
	if err := Convert_v1alpha2_BundleStatus_To_v1alpha1_BundleStatus(&src.Status, &dst.Status, nil); err != nil {
		return err
	}
	return nil
}

func Convert_v1alpha2_BundleTarget_To_v1alpha1_BundleTarget(in *trustv1alpha2.BundleTarget, out *BundleTarget, _ apimachineryconversion.Scope) error {
	for _, tkv := range in.Secret {
		if tkv.Format == "" || tkv.Format == trustv1alpha2.BundleFormatPEM {
			out.Secret = &KeySelector{Key: tkv.Key}
			break
		}
	}
	for _, tkv := range in.ConfigMap {
		if tkv.Format == "" || tkv.Format == trustv1alpha2.BundleFormatPEM {
			out.ConfigMap = &KeySelector{Key: tkv.Key}
			break
		}
	}

	var jks *JKS
	var pkcs12 *PKCS12
	for _, tkv := range slices.Concat(in.ConfigMap, in.Secret) {
		switch tkv.Format {
		case trustv1alpha2.BundleFormatJKS:
			jks = &JKS{}
			jks.Key = tkv.Key
			if tkv.JKS != nil {
				jks.Password = tkv.JKS.Password
			}
		case trustv1alpha2.BundleFormatPKCS12:
			pkcs12 = &PKCS12{}
			pkcs12.Key = tkv.Key
			if tkv.PKCS12 != nil {
				pkcs12.Password = tkv.PKCS12.Password
				pkcs12.Profile = PKCS12Profile(tkv.PKCS12.Profile)
				if pkcs12.Profile == "" {
					// Default profile changed from LegacyRC2 to LegacyDES in v1alpha1->v1alpha2
					pkcs12.Profile = LegacyDESPKCS12Profile
				}

			}
		}
		if jks != nil && pkcs12 != nil {
			break
		}
	}
	if jks != nil || pkcs12 != nil {
		out.AdditionalFormats = &AdditionalFormats{}
		if jks != nil {
			out.AdditionalFormats.JKS = jks
		}
		if pkcs12 != nil {
			out.AdditionalFormats.PKCS12 = pkcs12
		}
	}

	out.NamespaceSelector = in.NamespaceSelector
	return nil
}
