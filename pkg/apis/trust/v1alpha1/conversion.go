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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachineryconversion "k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/conversion"

	trustv1alpha2 "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
)

const annotationKeyJKSKey = "internal.trust-manager.io/jks-key"

func (src *Bundle) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*trustv1alpha2.ClusterBundle)
	dst.ObjectMeta = src.ObjectMeta

	scheme := runtime.NewScheme()
	if err := localSchemeBuilder.AddToScheme(scheme); err != nil {
		return err
	}
	converter := scheme.Converter()

	meta := &apimachineryconversion.Meta{
		Context: &dst.ObjectMeta,
	}
	if err := converter.Convert(&src.Spec, &dst.Spec, meta); err != nil {
		return err
	}
	if err := converter.Convert(&src.Status, &dst.Status, meta); err != nil {
		return err
	}
	return nil
}

func Convert_v1alpha1_BundleTarget_To_v1alpha2_BundleTarget(in *BundleTarget, out *trustv1alpha2.BundleTarget, scope apimachineryconversion.Scope) error {
	if err := autoConvert_v1alpha1_BundleTarget_To_v1alpha2_BundleTarget(in, out, scope); err != nil {
		return err
	}

	if in.AdditionalFormats != nil {
		appendTargetKV := func(tkv trustv1alpha2.TargetKeyValue) {
			if in.ConfigMap != nil {
				out.ConfigMap.Data = append(out.ConfigMap.Data, tkv)
			}
			if in.Secret != nil {
				out.Secret.Data = append(out.Secret.Data, tkv)
			}
		}

		if in.AdditionalFormats.JKS != nil {
			targetKV := trustv1alpha2.TargetKeyValue{
				Key:    in.AdditionalFormats.JKS.Key,
				Format: trustv1alpha2.BundleFormatPKCS12,
				PKCS12: trustv1alpha2.PKCS12{
					Password: in.AdditionalFormats.JKS.Password,
				},
			}
			appendTargetKV(targetKV)

			objMeta := scope.Meta().Context.(*metav1.ObjectMeta)
			if objMeta.Annotations == nil {
				objMeta.Annotations = map[string]string{}
			}
			objMeta.Annotations[annotationKeyJKSKey] = targetKV.Key
		}
		if in.AdditionalFormats.PKCS12 != nil {
			targetKV := trustv1alpha2.TargetKeyValue{
				Key:    in.AdditionalFormats.PKCS12.Key,
				Format: trustv1alpha2.BundleFormatPKCS12,
				PKCS12: trustv1alpha2.PKCS12{},
			}
			if err := Convert_v1alpha1_PKCS12_To_v1alpha2_PKCS12(in.AdditionalFormats.PKCS12, &targetKV.PKCS12, scope); err != nil {
				return err
			}
			appendTargetKV(targetKV)
		}
	}

	if out.NamespaceSelector == nil {
		// NamespaceSelector is required in v1alpha2
		out.NamespaceSelector = &metav1.LabelSelector{}
	}
	return nil
}

func Convert_v1alpha1_TargetTemplate_To_v1alpha2_KeyValueTarget(in *TargetTemplate, out *trustv1alpha2.KeyValueTarget, scope apimachineryconversion.Scope) error {
	out.Data = []trustv1alpha2.TargetKeyValue{{Key: in.Key}}
	if in.Metadata != nil {
		out.Metadata = &trustv1alpha2.TargetMetadata{}
		if err := Convert_v1alpha1_TargetMetadata_To_v1alpha2_TargetMetadata(in.Metadata, out.Metadata, scope); err != nil {
			return err
		}
	}
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

	scheme := runtime.NewScheme()
	if err := localSchemeBuilder.AddToScheme(scheme); err != nil {
		return err
	}
	converter := scheme.Converter()

	meta := &apimachineryconversion.Meta{
		Context: &dst.ObjectMeta,
	}
	if err := converter.Convert(&src.Spec, &dst.Spec, meta); err != nil {
		return err
	}
	if err := converter.Convert(&src.Status, &dst.Status, meta); err != nil {
		return err
	}
	return nil
}

func Convert_v1alpha2_BundleTarget_To_v1alpha1_BundleTarget(in *trustv1alpha2.BundleTarget, out *BundleTarget, scope apimachineryconversion.Scope) error {
	if err := autoConvert_v1alpha2_BundleTarget_To_v1alpha1_BundleTarget(in, out, scope); err != nil {
		return err
	}

	var targetKeyValues []trustv1alpha2.TargetKeyValue
	if in.Secret != nil {
		targetKeyValues = append(targetKeyValues, in.Secret.Data...)
	}
	if in.ConfigMap != nil {
		targetKeyValues = append(targetKeyValues, in.ConfigMap.Data...)
	}

	objMeta := scope.Meta().Context.(*metav1.ObjectMeta)

	var jks *JKS
	var pkcs12 *PKCS12
	for _, tkv := range targetKeyValues {
		if tkv.Format == trustv1alpha2.BundleFormatPKCS12 {
			if k, ok := objMeta.Annotations[annotationKeyJKSKey]; ok && k == tkv.Key {
				jks = &JKS{}
				jks.Key = tkv.Key
				jks.Password = tkv.PKCS12.Password
			} else {
				pkcs12 = &PKCS12{}
				pkcs12.Key = tkv.Key
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
		out.AdditionalFormats = &AdditionalFormats{
			JKS:    jks,
			PKCS12: pkcs12,
		}
	}

	delete(objMeta.Annotations, annotationKeyJKSKey)
	if len(objMeta.Annotations) == 0 {
		objMeta.Annotations = nil
	}

	return nil
}

func Convert_v1alpha2_KeyValueTarget_To_v1alpha1_TargetTemplate(in *trustv1alpha2.KeyValueTarget, out *TargetTemplate, scope apimachineryconversion.Scope) error {
	for _, tkv := range in.Data {
		if tkv.Format == "" || tkv.Format == trustv1alpha2.BundleFormatPEM {
			out.Key = tkv.Key
			break
		}
	}
	if in.Metadata != nil {
		out.Metadata = &TargetMetadata{}
		if err := Convert_v1alpha2_TargetMetadata_To_v1alpha1_TargetMetadata(in.Metadata, out.Metadata, scope); err != nil {
			return err
		}
	}
	return nil
}
