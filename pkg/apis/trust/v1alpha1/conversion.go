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
	conv "k8s.io/apimachinery/pkg/conversion"
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

func Convert_v1alpha1_JKS_To_v1alpha2_JKS(jks *JKS, jks2 *trustv1alpha2.JKS, scope conv.Scope) error {
	return nil
}

func Convert_v1alpha1_PKCS12_To_v1alpha2_PKCS12(pkcs12 *PKCS12, pkcs13 *trustv1alpha2.PKCS12, scope conv.Scope) error {
	return nil
}

func Convert_v1alpha2_BundleTarget_To_v1alpha1_BundleTarget(target *trustv1alpha2.BundleTarget, target2 *BundleTarget, scope conv.Scope) error {
	return nil
}

func Convert_v1alpha1_BundleTarget_To_v1alpha2_BundleTarget(target *BundleTarget, target2 *trustv1alpha2.BundleTarget, scope conv.Scope) error {
	return nil
}
