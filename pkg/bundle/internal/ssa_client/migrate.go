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
	"context"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/csaupgrade"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// crRegressionFieldManager is the field manager that was introduced by a regression in controller-runtime
	// version 0.15.0; fixed in 15.1 and 0.16.0: https://github.com/kubernetes-sigs/controller-runtime/pull/2435
	// trust-manager 0.6.0 was released with this regression in controller-runtime, which means that we have to
	// take extra care when migrating from CSA to SSA.
	crRegressionFieldManager = "Go-http-client"
)

// / MIGRATION: This is a migration function that migrates the ownership of
// fields from the Update operation to the Apply operation. This is required
// to ensure that the apply operations will also remove fields that were
// created by the Update operation.
func MigrateToApply(ctx context.Context, c client.Client, obj client.Object, opts ...csaupgrade.Option) (bool, error) {
	patch, err := csaupgrade.UpgradeManagedFieldsPatch(obj, sets.New(string(FieldManager), crRegressionFieldManager), string(FieldManager), opts...)
	if err != nil {
		return false, err
	}
	if patch != nil {
		return true, c.Patch(ctx, obj, client.RawPatch(types.JSONPatchType, patch))
	}
	// No work to be done - already upgraded
	return false, nil
}
