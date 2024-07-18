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
	"encoding/hex"
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	v1 "k8s.io/client-go/applyconfigurations/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
)

const (
	// BundleInjectBundleNameLabelKey is the key of the label that will trigger the injection of bundle data into the resource.
	// The label value should be the name of the bundle to inject data from.
	BundleInjectBundleNameLabelKey = "inject.trust-manager.io/bundle-name"
	// BundleInjectKeyLabelKey is the key for an optional label to specify the key to inject the bundle data into the resource.
	// The bundle data will be injected into the 'ca-bundle.crt' key if this label is not found in resource.
	BundleInjectKeyLabelKey = "inject.trust-manager.io/key"
)

type Injector struct {
	client.Client
	bundleBuilder *source.BundleBuilder
}

func (i *Injector) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	i.bundleBuilder = &source.BundleBuilder{
		Reader:  mgr.GetClient(),
		Options: opts,
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("configmap-injector").
		For(&metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}},
			builder.WithPredicates(
				hasLabelPredicate(BundleInjectBundleNameLabelKey),
			),
		).
		Complete(i)
}

func (i *Injector) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	target := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
	}

	if err := i.Get(ctx, request.NamespacedName, target); err != nil {
		if apierrors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	bundleName := target.GetLabels()[BundleInjectBundleNameLabelKey]
	if bundleName == "" {
		return reconcile.Result{}, nil
	}

	bundle := &trustapi.Bundle{}
	if err := i.Get(ctx, types.NamespacedName{Name: bundleName}, bundle); err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to look up bundle %q: %w", bundleName, err)
	}

	// TODO: Add support for additional formats
	bundleData, err := i.bundleBuilder.BuildBundle(ctx, bundle.Spec.Sources, nil)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to build bundle %q: %w", bundleName, err)
	}
	key := target.GetLabels()[BundleInjectKeyLabelKey]
	if key == "" {
		key = "ca-bundle.crt"
	}

	applyConfig := v1.ConfigMap(request.Name, request.Namespace).
		WithAnnotations(map[string]string{
			trustapi.BundleHashAnnotationKey: trustBundleHash([]byte(bundleData.Data)),
		}).
		WithData(map[string]string{key: bundleData.Data})

	return reconcile.Result{}, patchConfigMap(ctx, i.Client, applyConfig)
}

func trustBundleHash(data []byte) string {
	hash := sha256.New()
	_, _ = hash.Write(data)
	hashValue := [32]byte{}
	hash.Sum(hashValue[:0])
	dataHash := hex.EncodeToString(hashValue[:])
	return dataHash
}

type Cleaner struct {
	client.Client
}

func (c *Cleaner) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("configmap-injector-cleaner").
		For(&metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}},
			builder.WithPredicates(
				hasAnnotationPredicate(trustapi.BundleHashAnnotationKey),
				predicate.Not(hasLabelPredicate(BundleInjectBundleNameLabelKey)),
			),
		).
		Complete(c)
}

func (c *Cleaner) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	applyConfig := v1.ConfigMap(request.Name, request.Namespace)

	return reconcile.Result{}, patchConfigMap(ctx, c.Client, applyConfig)
}

func patchConfigMap(ctx context.Context, c client.Client, applyConfig *v1.ConfigMapApplyConfiguration) error {
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *applyConfig.Name,
			Namespace: *applyConfig.Namespace,
		},
	}

	encodedPatch, err := json.Marshal(applyConfig)
	if err != nil {
		return err
	}

	return c.Patch(ctx, obj, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager, client.ForceOwnership)
}

func hasLabelPredicate(key string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		_, ok := obj.GetLabels()[key]
		return ok
	})
}

func hasAnnotationPredicate(key string) predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		_, ok := obj.GetAnnotations()[key]
		return ok
	})
}
