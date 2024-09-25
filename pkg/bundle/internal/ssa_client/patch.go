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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/fieldpath"
)

const (
	FieldManager = client.FieldOwner("trust-manager")
)

type ApplyPatch struct {
	Patch []byte
}

var _ client.Patch = ApplyPatch{}

func (p ApplyPatch) Data(_ client.Object) ([]byte, error) {
	return p.Patch, nil
}

func (p ApplyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

// ManagedFieldEntries is a test utility function creating managed field entries
// for testing target configmaps and secrets.
func ManagedFieldEntries(fields []string, dataFields []string) []metav1.ManagedFieldsEntry {
	fieldset := fieldpath.NewSet()
	for _, property := range fields {
		fieldset.Insert(
			fieldpath.MakePathOrDie("data", property),
		)
	}
	for _, property := range dataFields {
		fieldset.Insert(
			fieldpath.MakePathOrDie("binaryData", property),
		)
	}

	jsonFieldSet, err := fieldset.ToJSON()
	if err != nil {
		panic(err)
	}

	return []metav1.ManagedFieldsEntry{
		{
			Manager:   "trust-manager",
			Operation: metav1.ManagedFieldsOperationApply,
			FieldsV1: &metav1.FieldsV1{
				Raw: jsonFieldSet,
			},
		},
	}
}
