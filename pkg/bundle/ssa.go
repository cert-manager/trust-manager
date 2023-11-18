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

package bundle

import (
	"context"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapiac "github.com/cert-manager/trust-manager/pkg/applyconfigurations/trust/v1alpha1"
)

// There is currently no common interface for apply configurations, ref. https://github.com/kubernetes/kubernetes/issues/118138.
// This is current blocker for first-class SSA support in controller runtime client.
// So for now we will use a simple type constraint with Go generics to avoid using the `any` type.

// Golang does not support type parameters on methods, ref. https://github.com/golang/go/issues/49085,
// so following the established pattern to use bundle as receiver does not work here.

// applyConfiguration is a type constraint for apply configurations in use in this package.
type applyConfiguration interface {
	*trustapiac.BundleApplyConfiguration | *corev1.ConfigMapApplyConfiguration | *corev1.SecretApplyConfiguration
}

// patchResource patches the resource using SSA forcing ownership of fields
func patchResource[AC applyConfiguration](ctx context.Context, w client.Writer, ac AC) error {
	o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ac)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: o}

	return w.Patch(ctx, u, client.Apply, client.ForceOwnership, client.FieldOwner(fieldManager))
}

// patchStatus patches the status subresource using SSA forcing ownership of fields
func patchStatus[AC applyConfiguration](ctx context.Context, w client.SubResourceWriter, ac AC) error {
	o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ac)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: o}

	return w.Patch(ctx, u, client.Apply, client.ForceOwnership, client.FieldOwner(fieldManager))
}

// deleteResource deletes the resource accepting apply configuration as input
func deleteResource[AC applyConfiguration](ctx context.Context, w client.Writer, ac AC) error {
	o, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ac)
	if err != nil {
		return err
	}
	u := &unstructured.Unstructured{Object: o}

	return w.Delete(ctx, u)
}
