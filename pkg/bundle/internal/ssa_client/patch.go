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
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/fieldpath"
)

const (
	FieldManager = client.FieldOwner("trust-manager")
	// CRRegressionFieldManager is the field manager that was introduced by a regression in controller-runtime
	// version 0.15.0; fixed in 15.1 and 0.16.0: https://github.com/kubernetes-sigs/controller-runtime/pull/2435
	// trust-manager 0.6.0 was released with this regression in controller-runtime, which means that we have to
	// take extra care when migrating from CSA to SSA.
	CRRegressionFieldManager = "Go-http-client"
)

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

func ManagedFieldEntries(fields []string, dataFields []string) []v1.ManagedFieldsEntry {
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

	return []v1.ManagedFieldsEntry{
		{
			Manager:   "trust-manager",
			Operation: v1.ManagedFieldsOperationApply,
			FieldsV1: &v1.FieldsV1{
				Raw: jsonFieldSet,
			},
		},
	}
}
