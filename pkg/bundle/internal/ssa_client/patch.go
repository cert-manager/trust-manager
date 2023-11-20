/*
Copyright 2021 The cert-manager Authors.

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

package ssa_client

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustapiac "github.com/cert-manager/trust-manager/pkg/applyconfigurations/trust/v1alpha1"
)

func GenerateBundlePatch(
	bundlePatch *trustapiac.BundleApplyConfiguration,
) (*trustapi.Bundle, client.Patch, error) {
	if bundlePatch == nil || bundlePatch.Name == nil {
		panic("bundlePatch must be non-nil and have a name")
	}

	// This object is used to deduce the name + unmarshall the return value in
	bundle := &trustapi.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: *bundlePatch.Name,
		},
	}

	encodedPatch, err := json.Marshal(bundlePatch)
	if err != nil {
		return bundle, nil, err
	}

	return bundle, applyPatch{encodedPatch}, nil
}

func GenerateConfigMapPatch(
	configmapPatch *coreapplyconfig.ConfigMapApplyConfiguration,
) (*corev1.ConfigMap, client.Patch, error) {
	if configmapPatch == nil || configmapPatch.Name == nil || configmapPatch.Namespace == nil {
		panic("configmapPatch must be non-nil and have a name and namespace")
	}

	// This object is used to deduce the name & namespace + unmarshall the return value in
	configmap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *configmapPatch.Name,
			Namespace: *configmapPatch.Namespace,
		},
	}

	encodedPatch, err := json.Marshal(configmapPatch)
	if err != nil {
		return configmap, nil, err
	}

	return configmap, applyPatch{encodedPatch}, nil
}

func GenerateSecretPatch(
	secretPatch *coreapplyconfig.SecretApplyConfiguration,
) (*corev1.Secret, client.Patch, error) {
	if secretPatch == nil || secretPatch.Name == nil || secretPatch.Namespace == nil {
		panic("secretPatch must be non-nil and have a name and namespace")
	}

	// This object is used to deduce the name & namespace + unmarshall the return value in
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *secretPatch.Name,
			Namespace: *secretPatch.Namespace,
		},
	}

	encodedPatch, err := json.Marshal(secretPatch)
	if err != nil {
		return secret, nil, err
	}

	return secret, applyPatch{encodedPatch}, nil
}

type applyPatch struct {
	patch []byte
}

var _ client.Patch = applyPatch{}

func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return p.patch, nil
}

func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}
