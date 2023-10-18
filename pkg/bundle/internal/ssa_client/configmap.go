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
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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
