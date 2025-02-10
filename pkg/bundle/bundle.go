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
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/csaupgrade"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/target"
	"github.com/cert-manager/trust-manager/pkg/options"
)

// bundle is a controller-runtime controller. Implements the actual controller
// logic by reconciling over Bundles.
type bundle struct {
	// a cache-backed Kubernetes client
	client client.Client

	// recorder is used for create Kubernetes Events for reconciled Bundles.
	recorder record.EventRecorder

	// clock returns time which can be overwritten for testing.
	clock clock.Clock

	// Options holds options for the Bundle controller.
	Options options.Bundle

	sources *target.BundleBuilder

	targetReconciler *target.Reconciler
}

// Reconcile is the top level function for reconciling over synced Bundles.
// Reconcile will be called whenever a Bundle event happens, or whenever any
// related resource event to that bundle occurs.
func (b *bundle) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	result, statusPatch, resultErr := b.reconcileBundle(ctx, req)
	if statusPatch != nil {
		con, patch, err := ssa_client.GenerateBundleStatusPatch(req.Name, statusPatch)
		if err != nil {
			err = fmt.Errorf("failed to generate bundle status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}

		if err := b.client.Status().Patch(ctx, con, patch, ssa_client.FieldManager, client.ForceOwnership); err != nil {
			err = fmt.Errorf("failed to apply bundle status patch: %w", err)
			return ctrl.Result{}, utilerrors.NewAggregate([]error{resultErr, err})
		}
	}

	return result, resultErr
}

func (b *bundle) reconcileBundle(ctx context.Context, req ctrl.Request) (result ctrl.Result, statusPatch *trustapi.BundleStatus, returnedErr error) {
	log := logf.FromContext(ctx).WithValues("bundle", req.NamespacedName.Name)
	ctx = logf.IntoContext(ctx, log)
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
	if didMigrate, err := ssa_client.MigrateToApply(ctx, b.client, &bundle, csaupgrade.Subresource("status")); err != nil {
		log.Error(err, "failed to migrate bundle status")
		return ctrl.Result{}, nil, fmt.Errorf("failed to migrate bundle status: %w", err)
	} else if didMigrate {
		log.V(2).Info("migrated bundle status from CSA to SSA")
	}

	// Initialize patch with current status field values, except conditions.
	// This is done to ensure information is not lost in patch if exiting early.
	statusPatch = &trustapi.BundleStatus{
		DefaultCAPackageVersion: bundle.Status.DefaultCAPackageVersion,
	}
	resolvedBundle, err := b.sources.BuildBundle(ctx, bundle.Spec.Sources, bundle.Spec.Target.AdditionalFormats)

	// If any source is not found, update the Bundle status to an unready state.
	if errors.As(err, &target.SourceNotFoundError{}) {
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

	// Detect if we have a bundle with Secret targets but the feature is disabled.
	if !b.Options.SecretTargetsEnabled && bundle.Spec.Target.Secret != nil {

		log.Error(err, "bundle has Secret targets but the feature is disabled")
		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SecretTargetsDisabled", "Bundle has Secret targets but the feature is disabled")

		b.setBundleCondition(
			bundle.Status.Conditions,
			&statusPatch.Conditions,
			trustapi.BundleCondition{
				Type:               trustapi.BundleConditionSynced,
				Status:             metav1.ConditionFalse,
				Reason:             "SecretTargetsDisabled",
				Message:            "Bundle has Secret targets but the feature is disabled",
				ObservedGeneration: bundle.Generation,
			},
		)

		return ctrl.Result{}, statusPatch, nil
	}

	targetResources := map[target.Resource]bool{}

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

			namespacedName := types.NamespacedName{
				Name:      bundle.Name,
				Namespace: namespace.Name,
			}

			if bundle.Spec.Target.Secret != nil {
				targetResources[target.Resource{Kind: target.KindSecret, NamespacedName: namespacedName}] = true
			}
			if bundle.Spec.Target.ConfigMap != nil {
				targetResources[target.Resource{Kind: target.KindConfigMap, NamespacedName: namespacedName}] = true
			}
		}
	}

	// Find all old existing target resources.
	targetKinds := []target.Kind{target.KindConfigMap}
	if b.Options.SecretTargetsEnabled {
		targetKinds = append(targetKinds, target.KindSecret)
	}
	for _, kind := range targetKinds {
		targetList := &metav1.PartialObjectMetadataList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       string(kind),
			},
		}
		err := b.targetReconciler.Cache.List(ctx, targetList, &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{
				trustapi.BundleLabelKey: bundle.Name,
			}),
		})
		if err != nil {
			log.Error(err, "failed to list targets", "kind", kind)
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, fmt.Sprintf("%sListError", kind), "Failed to list %ss: %s", strings.ToLower(string(kind)), err)
			return ctrl.Result{}, nil, fmt.Errorf("failed to list %ss: %w", kind, err)
		}

		for _, t := range targetList.Items {
			key := target.Resource{
				Kind: kind,
				NamespacedName: types.NamespacedName{
					Name:      t.Name,
					Namespace: t.Namespace,
				},
			}

			targetLog := log.WithValues("target", key)

			if _, ok := targetResources[key]; ok {
				// This target is still a target, so we don't need to remove it.
				continue
			}

			// Don't reconcile target for targets that are being deleted.
			if t.GetDeletionTimestamp() != nil {
				targetLog.V(2).WithValues("deletionTimestamp", t.GetDeletionTimestamp()).Info("skipping sync for target as it is being deleted")
				continue
			}

			if !metav1.IsControlledBy(&t, &bundle) /* #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010 */ {
				targetLog.V(2).Info("skipping sync for target as it is not controlled by bundle")
				continue
			}

			targetResources[key] = false
		}
	}

	var needsUpdate bool

	for t, shouldExist := range targetResources {
		targetLog := log.WithValues("target", t)
		synced, err := b.targetReconciler.Sync(logf.IntoContext(ctx, targetLog), t, &bundle, resolvedBundle.Data, shouldExist)
		if err != nil {
			targetLog.Error(err, "failed sync bundle to target namespace")
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, fmt.Sprintf("Sync%sTargetFailed", t.Kind), "Failed to sync target %s in Namespace %q: %s", t.Kind, t.Namespace, err)

			b.setBundleCondition(
				bundle.Status.Conditions,
				&statusPatch.Conditions,
				trustapi.BundleCondition{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             fmt.Sprintf("Sync%sTargetFailed", t.Kind),
					Message:            fmt.Sprintf("Failed to sync bundle %s to namespace %q: %s", t.Kind, t.Namespace, err),
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

	if b.setBundleStatusDefaultCAVersion(statusPatch, resolvedBundle.DefaultCAPackageStringID) {
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

	// LabelSelectorAsSelector returns a Selector selecting nothing if LabelSelector is nil,
	// while our current default is to select everything. But this is subject to change.
	// See https://github.com/cert-manager/trust-manager/issues/39
	if nsSelector == nil {
		return labels.Everything(), nil
	}

	return metav1.LabelSelectorAsSelector(nsSelector)
}
