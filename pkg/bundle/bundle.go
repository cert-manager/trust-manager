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
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
)

// Options hold options for the Bundle controller.
type Options struct {
	// Log is the Bundle controller logger.
	Log logr.Logger

	// Namespace is the trust Namespace that source data can be referenced.
	Namespace string

	// DefaultPackageLocation is the location on the filesystem from which the 'default'
	// certificate package should be loaded. If set, a valid package must be successfully
	// loaded in order for the controller to start. If unset, referring to the default
	// certificate package in a `Bundle` resource will cause that Bundle to error.
	DefaultPackageLocation string
}

// bundle is a controller-runtime controller. Implements the actual controller
// logic by reconciling over Bundles.
type bundle struct {
	// a cache-backed Kubernetes client
	client client.Client

	// a direct Kubernetes client (only used for CSA to CSA migration)
	directClient client.Client

	// targetCache is a cache.Cache that holds cached ConfigMap
	// resources that are used as targets for Bundles.
	targetCache client.Reader

	// defaultPackage holds the loaded 'default' certificate package, if one was specified
	// at startup.
	defaultPackage *fspkg.Package

	// recorder is used for create Kubernetes Events for reconciled Bundles.
	recorder record.EventRecorder

	// clock returns time which can be overwritten for testing.
	clock clock.Clock

	// Options holds options for the Bundle controller.
	Options

	// patchResourceOverwrite allows use to override the patchResource function
	// it is used for testing purposes
	patchResourceOverwrite func(ctx context.Context, obj interface{}) error
}

// Reconcile is the top level function for reconciling over synced Bundles.
// Reconcile will be called whenever a Bundle event happens, or whenever any
// related resource event to that bundle occurs.
func (b *bundle) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result, statusPatch, resultErr := b.reconcileBundle(ctx, req)
	if statusPatch != nil {
		con, patch, err := ssa_client.GenerateBundleStatusPatch(req.Name, req.Namespace, statusPatch)
		if err != nil {
			err = fmt.Errorf("failed to generate bundle status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}

		if err := b.client.Status().Patch(ctx, con, patch, &client.SubResourcePatchOptions{
			PatchOptions: client.PatchOptions{
				FieldManager: fieldManager,
				Force:        ptr.To(true),
			},
		}); err != nil {
			err = fmt.Errorf("failed to apply bundle status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}
	}

	return result, resultErr
}

func (b *bundle) reconcileBundle(ctx context.Context, req ctrl.Request) (result ctrl.Result, statusPatch *trustapi.BundleStatus, returnedErr error) {
	log := b.Log.WithValues("bundle", req.NamespacedName.Name)
	log.V(2).Info("syncing bundle")

	var bundle trustapi.Bundle
	err := b.client.Get(ctx, req.NamespacedName, &bundle)
	if apierrors.IsNotFound(err) {
		log.V(2).Info("bundle no longer exists, ignoring")
		return ctrl.Result{}, nil, nil
	}

	if err != nil {
		log.Error(err, "failed to get bundle")
		return ctrl.Result{}, nil, fmt.Errorf("failed to get %q: %s", req.NamespacedName, err)
	}

	// MIGRATION: If we are upgrading from a version of trust-manager that did use Update to set
	// the Bundle status, we need to ensure that we do remove the old status fields in case we apply.
	if didMigrate, err := b.migrateBundleStatusToApply(ctx, &bundle); err != nil {
		log.Error(err, "failed to migrate bundle status")
		return ctrl.Result{}, nil, fmt.Errorf("failed to migrate bundle status: %w", err)
	} else if didMigrate {
		log.V(2).Info("migrated bundle status from CSA to SSA")
	}

	statusPatch = &trustapi.BundleStatus{}

	resolvedBundle, err := b.buildSourceBundle(ctx, &bundle)

	// If any source is not found, update the Bundle status to an unready state.
	if errors.As(err, &notFoundError{}) {
		log.Error(err, "bundle source was not found")
		b.setBundleCondition(
			bundle.Status.Conditions,
			&statusPatch.Conditions,
			trustapi.BundleCondition{
				Type:               trustapi.BundleConditionSynced,
				Status:             metav1.ConditionFalse,
				Reason:             "SourceNotFound",
				Message:            "Bundle source was not found: " + err.Error(),
				ObservedGeneration: bundle.Generation,
			},
		)

		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SourceNotFound", "Bundle source was not found: %s", err)

		return ctrl.Result{}, statusPatch, nil
	}

	if err != nil {
		log.Error(err, "failed to build source bundle")
		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SourceBuildError", "Failed to build bundle sources: %s", err)
		return ctrl.Result{}, nil, fmt.Errorf("failed to build bundle source: %w", err)
	}

	statusPatch.Target = &bundle.Spec.Target

	targetResources := map[types.NamespacedName]bool{}

	namespaceSelector, err := b.bundleTargetNamespaceSelector(&bundle)
	if err != nil {
		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "NamespaceSelectorError", "Failed to build namespace match labels selector: %s", err)
		return ctrl.Result{}, nil, fmt.Errorf("failed to build NamespaceSelector: %w", err)
	}

	// Find all desired targetResources.
	{
		var namespaceList corev1.NamespaceList
		if err := b.client.List(ctx, &namespaceList, &client.ListOptions{
			LabelSelector: namespaceSelector,
		}); err != nil {
			log.Error(err, "failed to list namespaces")
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "NamespaceListError", "Failed to list namespaces: %s", err)
			return ctrl.Result{}, nil, fmt.Errorf("failed to list Namespaces: %w", err)
		}
		for _, namespace := range namespaceList.Items {
			namespaceLog := log.WithValues("namespace", namespace.Name)

			// Don't reconcile target for Namespaces that are being terminated.
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				namespaceLog.V(2).WithValues("phase", corev1.NamespaceTerminating).Info("skipping sync for namespace as it is terminating")
				continue
			}

			targetResources[types.NamespacedName{
				Name:      bundle.Name,
				Namespace: namespace.Name,
			}] = true
		}
	}

	// Find all old existing ConfigMap targetResources.
	{
		configMapList := &metav1.PartialObjectMetadataList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
		}
		err := b.targetCache.List(ctx, configMapList, &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{
				trustapi.BundleLabelKey: bundle.Name,
			}),
		})
		if err != nil {
			log.Error(err, "failed to list configmaps")
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "ConfigMapListError", "Failed to list configmaps: %s", err)
			return ctrl.Result{}, nil, fmt.Errorf("failed to list ConfigMaps: %w", err)
		}

		for _, configMap := range configMapList.Items {
			key := types.NamespacedName{
				Name:      configMap.Name,
				Namespace: configMap.Namespace,
			}

			configmapLog := log.WithValues("configmap", key)

			if _, ok := targetResources[key]; ok {
				// This ConfigMap is still a target, so we don't need to remove it.
				continue
			}

			// Don't reconcile target for ConfigMaps that are being deleted.
			if configMap.GetDeletionTimestamp() != nil {
				configmapLog.V(2).WithValues("deletionTimestamp", configMap.GetDeletionTimestamp()).Info("skipping sync for configmap as it is being deleted")
				continue
			}

			if !metav1.IsControlledBy(&configMap, &bundle) {
				configmapLog.V(2).Info("skipping sync for configmap as it is not controlled by bundle")
				continue
			}

			targetResources[key] = false
		}
	}

	var needsUpdate bool

	for target, shouldExist := range targetResources {
		targetLog := log.WithValues("target", target)

		synced, err := b.syncTarget(ctx, targetLog, &bundle, target.Name, target.Namespace, resolvedBundle.data, shouldExist)
		if err != nil {
			targetLog.Error(err, "failed sync bundle to target namespace")
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SyncTargetFailed", "Failed to sync target in Namespace %q: %s", target.Namespace, err)

			b.setBundleCondition(
				bundle.Status.Conditions,
				&statusPatch.Conditions,
				trustapi.BundleCondition{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SyncTargetFailed",
					Message:            fmt.Sprintf("Failed to sync bundle to namespace %q: %s", target.Namespace, err),
					ObservedGeneration: bundle.Generation,
				},
			)

			return ctrl.Result{Requeue: true}, statusPatch, nil
		}

		if synced {
			// We need to update if any target is synced.
			needsUpdate = true
		}
	}

	if bundle.Status.Target == nil || !apiequality.Semantic.DeepEqual(*bundle.Status.Target, bundle.Spec.Target) {
		needsUpdate = true
	}

	if b.setBundleStatusDefaultCAVersion(statusPatch, resolvedBundle.defaultCAPackageStringID) {
		needsUpdate = true
	}

	message := "Successfully synced Bundle to all namespaces"
	if !namespaceSelector.Empty() {
		message = fmt.Sprintf("Successfully synced Bundle to namespaces that match this label selector: %s", namespaceSelector)
	}

	syncedCondition := trustapi.BundleCondition{
		Type:               trustapi.BundleConditionSynced,
		Status:             metav1.ConditionTrue,
		Reason:             "Synced",
		Message:            message,
		ObservedGeneration: bundle.Generation,
	}

	if !needsUpdate && bundleHasCondition(bundle.Status.Conditions, syncedCondition) {
		return ctrl.Result{}, nil, nil
	}

	log.V(2).Info("successfully synced bundle")

	b.setBundleCondition(
		bundle.Status.Conditions,
		&statusPatch.Conditions,
		syncedCondition,
	)

	b.recorder.Eventf(&bundle, corev1.EventTypeNormal, "Synced", message)

	return ctrl.Result{}, statusPatch, nil
}

func (b *bundle) bundleTargetNamespaceSelector(bundleObj *trustapi.Bundle) (labels.Selector, error) {
	nsSelector := bundleObj.Spec.Target.NamespaceSelector

	if nsSelector == nil || nsSelector.MatchLabels == nil {
		return labels.Everything(), nil
	}

	return metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSelector.MatchLabels})
}

// MIGRATION: This is a migration function that migrates the ownership of
// fields from the Update operation to the Apply operation. This is required
// to ensure that the apply operations will also remove fields that were
// created by the Update operation.
func (b *bundle) migrateBundleStatusToApply(ctx context.Context, obj client.Object) (bool, error) {
	// isOldBundleStatusManagedFieldsEntry returns true if the given ManagedFieldsEntry is
	// an entry that was created by the old fieldManager and is an update to the status
	// subresource. We need to check for this as we need to migrate the entry to the new
	// fieldManager.
	isOldBundleStatusManagedFieldsEntry := func(mf *metav1.ManagedFieldsEntry) bool {
		return (mf.Manager == fieldManager || mf.Manager == crRegressionFieldManager) &&
			mf.Operation == metav1.ManagedFieldsOperationUpdate &&
			mf.Subresource == "status"
	}

	needsUpdate := false
	managedFields := obj.GetManagedFields()
	for i, mf := range managedFields {
		if !isOldBundleStatusManagedFieldsEntry(&mf) {
			continue
		}

		needsUpdate = true
		managedFields[i].Operation = metav1.ManagedFieldsOperationApply
		managedFields[i].Manager = fieldManager
	}

	if !needsUpdate {
		return false, nil
	}

	obj.SetManagedFields(managedFields)
	return true, b.directClient.Update(ctx, obj)
}
