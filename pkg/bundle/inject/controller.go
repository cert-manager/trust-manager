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

package inject

import (
	"context"
	"crypto/sha256"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
)

const (
	BundleInjectLabelKey = "trust-manager.io/inject-bundle"

	fieldManager = "trust-manager-injector"
)

var configMap = &metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}}

type Injector struct {
	client.Client
}

func (i *Injector) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("configmap-injector").
		For(configMap,
			builder.WithPredicates(
				hasLabel(BundleInjectLabelKey),
			)).
		Complete(i)
}

func (i *Injector) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	data := map[string]string{"ca.crt": "bundle data"}
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte("bundle data hash")))

	applyConfig := v1.ConfigMap(request.Name, request.Namespace).
		WithAnnotations(map[string]string{v1alpha1.BundleHashAnnotationKey: dataHash}).
		WithData(data)

	return reconcile.Result{}, patchConfigMap(ctx, i.Client, applyConfig)
}

type Cleaner struct {
	client.Client
}

func (c *Cleaner) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("configmap-injector-cleaner").
		For(configMap,
			builder.WithPredicates(
				hasAnnotation(v1alpha1.BundleHashAnnotationKey),
				predicate.Not(hasLabel(BundleInjectLabelKey)),
			)).
		Complete(c)
}

func (c *Cleaner) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	applyConfig := v1.ConfigMap(request.Name, request.Namespace)

	return reconcile.Result{}, patchConfigMap(ctx, c.Client, applyConfig)
}

func patchConfigMap(ctx context.Context, c client.Client, applyConfig *v1.ConfigMapApplyConfiguration) error {
	configMap, patch, err := ssa_client.GenerateConfigMapPatch(applyConfig)
	if err != nil {
		return err
	}

	return c.Patch(ctx, configMap, patch, client.FieldOwner(fieldManager), client.ForceOwnership)
}

func hasLabel(key string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		_, ok := obj.GetLabels()[key]
		return ok
	})
}

func hasAnnotation(key string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		_, ok := obj.GetAnnotations()[key]
		return ok
	})
}
