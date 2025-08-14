package controller

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
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
		For(&trustapi.Bundle{}).
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
	if err := r.Get(ctx, client.ObjectKeyFromObject(bundle), clusterBundle); !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get ClusterBundle: %w", err)
	}

	if isUserManaged(clusterBundle) {
		return client.IgnoreNotFound(r.unmanage(ctx, clusterBundle))
	}

	cb := clusterBundle.DeepCopy()
	if err := bundle.ConvertTo(cb); err != nil {
		return fmt.Errorf("failed to convert Bundle to ClusterBundle: %w", err)
	}
	cb.Status = trustmanagerapi.BundleStatus{}
	if err := ctrl.SetControllerReference(bundle, cb, r.Scheme()); err != nil {
		return fmt.Errorf("failed to set ClusterBundle controller reference: %w", err)
	}

	encodedPatch, err := json.Marshal(cb)
	if err != nil {
		return fmt.Errorf("failed to marshal ClusterBundle patch: %w", err)
	}

	return r.Patch(ctx, cb, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager, client.ForceOwnership)
}

func (r *BundleReconciler) unmanage(ctx context.Context, cb *trustmanagerapi.ClusterBundle) error {
	ac := trustmanagerac.ClusterBundle(cb.Name)

	encodedPatch, err := json.Marshal(ac)
	if err != nil {
		return fmt.Errorf("failed to marshal ClusterBundle patch: %w", err)
	}

	return r.Patch(ctx, cb, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager)
}

func isUserManaged(cb *trustmanagerapi.ClusterBundle) bool {
	for _, mf := range cb.ManagedFields {
		if !(mf.Operation == metav1.ManagedFieldsOperationApply &&
			mf.Manager == string(ssa_client.FieldManager)) {
			return true
		}
	}
	return false
}
