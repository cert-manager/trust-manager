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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

type bundleStatusApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	Status                           *trustapi.BundleStatus `json:"status,omitempty"`
}

func GenerateBundleStatusPatch(
	name string,
	status *trustapi.BundleStatus,
) (*trustapi.Bundle, client.Patch, error) {
	// This object is used to deduce the name & namespace + unmarshall the return value in
	bundle := &trustapi.Bundle{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}

	// This object is used to render the patch
	b := &bundleStatusApplyConfiguration{
		ObjectMetaApplyConfiguration: &v1.ObjectMetaApplyConfiguration{},
	}
	b.WithName(name)
	b.WithKind(trustapi.BundleKind)
	b.WithAPIVersion(trustapi.SchemeGroupVersion.Identifier())
	b.Status = status

	encodedPatch, err := json.Marshal(b)
	if err != nil {
		return bundle, nil, err
	}

	return bundle, ApplyPatch{encodedPatch}, nil
}
