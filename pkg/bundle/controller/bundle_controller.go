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

package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	trustmanagerac "github.com/cert-manager/trust-manager/pkg/applyconfigurations/trustmanager/v1alpha2"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
)

type BundleReconciler struct {
	client.Client
}

// SetupWithManager sets up the controller with the Manager.
func (r *BundleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&trustapi.Bundle{}). //lint:ignore SA1019
		Owns(&trustmanagerapi.ClusterBundle{}).
		Complete(r)
}

func (r *BundleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logf.FromContext(ctx).Info("Reconciling")

	bundle := &trustapi.Bundle{}
	if err := r.Get(ctx, req.NamespacedName, bundle); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	return ctrl.Result{}, r.reconcile(ctx, bundle)
}

func (r *BundleReconciler) reconcile(ctx context.Context, bundle *trustapi.Bundle) error {
	clusterBundle := &trustmanagerapi.ClusterBundle{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(bundle), clusterBundle); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("failed to get ClusterBundle: %w", err)
		}
	}

	if isClusterBundleUserManaged(clusterBundle) {
		if err := r.unmanageClusterBundle(ctx, clusterBundle); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to unmanaged ClusterBundle: %w", err)
		}
		return r.applyBundleCondition(ctx, bundle, metav1.Condition{
			Type:               trustapi.BundleConditionMigrated,
			Status:             metav1.ConditionTrue,
			Reason:             "MigrationDetected",
			Message:            "Bundle is migrated to ClusterBundle by user; this resource can be safely deleted.",
			ObservedGeneration: bundle.Generation,
		})
	}

	if err := r.applyClusterBundle(ctx, bundle); err != nil {
		return fmt.Errorf("failed to apply ClusterBundle: %w", err)
	}

	return r.applyBundleCondition(ctx, bundle, metav1.Condition{
		Type:               trustapi.BundleConditionDeprecated,
		Status:             metav1.ConditionTrue,
		Reason:             "MigrationRequired",
		Message:            "Bundle is deprecated; please migrate to ClusterBundle.",
		ObservedGeneration: bundle.Generation,
	})
}

func (r *BundleReconciler) applyClusterBundle(ctx context.Context, bundle *trustapi.Bundle) error {
	clusterBundle, err := convertBundleToClusterBundle(bundle)
	if err != nil {
		return err
	}
	if err := ctrl.SetControllerReference(bundle, clusterBundle, r.Scheme()); err != nil {
		return fmt.Errorf("failed to set ClusterBundle controller reference: %w", err)
	}

	encodedPatch, err := json.Marshal(clusterBundle)
	if err != nil {
		return fmt.Errorf("failed to marshal ClusterBundle patch: %w", err)
	}
	return r.Patch(ctx, clusterBundle, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager, client.ForceOwnership)
}

func (r *BundleReconciler) applyBundleCondition(ctx context.Context, bundle *trustapi.Bundle, condition metav1.Condition) error {
	meta.SetStatusCondition(&bundle.Status.Conditions, condition)

	bundleStatus := &trustapi.BundleStatus{
		Conditions: []metav1.Condition{*meta.FindStatusCondition(bundle.Status.Conditions, condition.Type)},
	}
	b, patch, err := ssa_client.GenerateBundleStatusPatch(bundle.Name, bundleStatus)
	if err != nil {
		return fmt.Errorf("failed to generate bundle status patch: %w", err)
	}

	return r.Status().Patch(ctx, b, patch, ssa_client.FieldManager, client.ForceOwnership)
}

func (r *BundleReconciler) unmanageClusterBundle(ctx context.Context, cb *trustmanagerapi.ClusterBundle) error {
	ac := trustmanagerac.ClusterBundle(cb.Name)

	encodedPatch, err := json.Marshal(ac)
	if err != nil {
		return fmt.Errorf("failed to marshal ClusterBundle patch: %w", err)
	}

	return r.Patch(ctx, cb, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager)
}

func isClusterBundleUserManaged(cb *trustmanagerapi.ClusterBundle) bool {
	_, ok := cb.Annotations[trustmanagerapi.BundleMigratedAnnotation]
	return ok
}

func convertBundleToClusterBundle(bundle *trustapi.Bundle) (*trustmanagerapi.ClusterBundle, error) {
	cb := &trustmanagerapi.ClusterBundle{}
	if err := bundle.ConvertTo(cb); err != nil {
		return nil, fmt.Errorf("failed to convert Bundle to ClusterBundle: %w", err)
	}

	clusterBundle := &trustmanagerapi.ClusterBundle{}
	clusterBundle.APIVersion = "trust-manager.io/v1alpha2"
	clusterBundle.Kind = "ClusterBundle"
	clusterBundle.Name = bundle.Name
	clusterBundle.Spec = cb.Spec
	return clusterBundle, nil
}
