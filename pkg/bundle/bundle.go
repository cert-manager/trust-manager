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
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
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
	// targetDirectClient is a Kubernetes client that makes calls to the API for every request.
	// Should be used for updating, deleting, and when requesting data from
	// resources whose informer only caches metadata.
	targetDirectClient client.Client

	// sourceLister makes requests to the informer cache. All cached source resources
	// are expected to be full objects in a single namespace (the TrustNamespace).
	sourceLister client.Reader

	// defaultPackage holds the loaded 'default' certificate package, if one was specified
	// at startup.
	defaultPackage *fspkg.Package

	// recorder is used for create Kubernetes Events for reconciled Bundles.
	recorder record.EventRecorder

	// clock returns time which can be overwritten for testing.
	clock clock.Clock

	// Options holds options for the Bundle controller.
	Options
}

// Reconcile is the top level function for reconciling over synced Bundles.
// Reconcile will be called whenever a Bundle event happens, or whenever any
// related resource event to that bundle occurs.
func (b *bundle) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := b.Log.WithValues("bundle", req.NamespacedName.Name)
	log.V(2).Info("syncing bundle")

	var bundle trustapi.Bundle
	err := b.sourceLister.Get(ctx, req.NamespacedName, &bundle)
	if apierrors.IsNotFound(err) {
		log.V(2).Info("bundle no longer exists, ignoring")
		return ctrl.Result{}, nil
	}

	if err != nil {
		log.Error(err, "failed to get bundle")
		return ctrl.Result{}, fmt.Errorf("failed to get %q: %s", req.NamespacedName, err)
	}

	namespaceSelector := labels.Everything()
	if nsSelector := bundle.Spec.Target.NamespaceSelector; nsSelector != nil && nsSelector.MatchLabels != nil {
		namespaceSelector, err = metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSelector.MatchLabels})
		if err != nil {
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "NamespaceSelectorError", "Failed to build namespace match labels selector: %s", err)
			return ctrl.Result{}, fmt.Errorf("failed to build NamespaceSelector: %w", err)
		}
	}

	var namespaceList corev1.NamespaceList
	if err := b.sourceLister.List(ctx, &namespaceList); err != nil {
		log.Error(err, "failed to list namespaces")
		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "NamespaceListError", "Failed to list namespaces: %s", err)
		return ctrl.Result{}, fmt.Errorf("failed to list Namespaces: %w", err)
	}

	// If the target has changed on the Spec, delete the old targets first.
	if bundle.Status.Target != nil && !apiequality.Semantic.DeepEqual(*bundle.Status.Target, bundle.Spec.Target) {
		log.Info("deleting old targets", "old_target", bundle.Status.Target)
		b.recorder.Eventf(&bundle, corev1.EventTypeNormal, "DeleteOldTarget", "Deleting old targets as Bundle target has been modified")

		for _, namespace := range namespaceList.Items {
			configMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundle.Name,
					Namespace: namespace.Name,
				},
			}

			err := b.targetDirectClient.Get(ctx, client.ObjectKeyFromObject(configMap), configMap)

			// Ignore ConfigMaps that have not been created yet, as they will be
			// created later on in the sync.
			if apierrors.IsNotFound(err) {
				continue
			}

			if err != nil {
				log.Error(err, "failed to get target ConfigMap")
				b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "TargetGetError", "Failed to get target ConfigMap: %s", err)
				return ctrl.Result{}, fmt.Errorf("failed to get target ConfigMap: %w", err)
			}

			delete(configMap.Data, bundle.Status.Target.ConfigMap.Key)

			if err := b.targetDirectClient.Update(ctx, configMap); err != nil {
				log.Error(err, "failed to delete old ConfigMap target key")
				b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "TargetUpdateError", "Failed to remove old key from ConfigMap target: %s", err)
				return ctrl.Result{}, fmt.Errorf("failed to delete old ConfigMap target key: %w", err)
			}

			log.V(2).Info("deleted old target key", "old_target", bundle.Status.Target, "namespace", namespace.Name)
		}

		// Return with update here, so targets are synced on the next Reconcile.
		bundle.Status.Target = &bundle.Spec.Target
		return ctrl.Result{}, b.targetDirectClient.Status().Update(ctx, &bundle)
	}

	resolvedBundle, err := b.buildSourceBundle(ctx, &bundle)

	// If any source is not found, update the Bundle status to an unready state.
	if errors.As(err, &notFoundError{}) {
		log.Error(err, "bundle source was not found")
		b.setBundleCondition(&bundle, trustapi.BundleCondition{
			Type:    trustapi.BundleConditionSynced,
			Status:  corev1.ConditionFalse,
			Reason:  "SourceNotFound",
			Message: "Bundle source was not found: " + err.Error(),
		})

		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SourceNotFound", "Bundle source was not found: %s", err)
		return ctrl.Result{}, b.targetDirectClient.Status().Update(ctx, &bundle)
	}

	if err != nil {
		log.Error(err, "failed to build source bundle")
		b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SourceBuildError", "Failed to build bundle sources: %s", err)
		return ctrl.Result{}, fmt.Errorf("failed to build bundle source: %w", err)
	}

	var needsUpdate bool
	for _, namespace := range namespaceList.Items {
		log = log.WithValues("namespace", namespace.Name)

		// Don't reconcile target for Namespaces that are being terminated.
		if namespace.Status.Phase == corev1.NamespaceTerminating {
			log.V(2).WithValues("phase", corev1.NamespaceTerminating).Info("skipping sync for namespace as it is terminating")
			continue
		}

		synced, err := b.syncTarget(ctx, log, &bundle, namespaceSelector, &namespace, resolvedBundle.data)
		if err != nil {
			log.Error(err, "failed sync bundle to target namespace")
			b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SyncTargetFailed", "Failed to sync target in Namespace %q: %s", namespace.Name, err)

			b.setBundleCondition(&bundle, trustapi.BundleCondition{
				Type:    trustapi.BundleConditionSynced,
				Status:  corev1.ConditionFalse,
				Reason:  "SyncTargetFailed",
				Message: fmt.Sprintf("Failed to sync bundle to namespace %q: %s", namespace.Name, err),
			})

			return ctrl.Result{Requeue: true}, b.targetDirectClient.Status().Update(ctx, &bundle)
		}

        secretSynced := false
        if bundle.Spec.Target.Secret != nil {
            var syncErr error
            secretSynced, syncErr = b.syncSecretTarget(ctx, log, &bundle, namespaceSelector, &namespace, []byte(resolvedBundle.data))
            if syncErr != nil {
                log.Error(syncErr, "failed sync bundle to target namespace")
                b.recorder.Eventf(&bundle, corev1.EventTypeWarning, "SyncTargetFailed", "Failed to sync secret target in Namespace %q: %s", namespace.Name, syncErr)

                b.setBundleCondition(&bundle, trustapi.BundleCondition{
                    Type:    trustapi.BundleConditionSynced,
                    Status:  corev1.ConditionFalse,
                    Reason:  "SyncTargetFailed",
                    Message: fmt.Sprintf("Failed to sync bundle target secret to namespace %q: %s", namespace.Name, syncErr),
                })

                return ctrl.Result{Requeue: true}, b.targetDirectClient.Status().Update(ctx, &bundle)
            }
        }

		if synced || secretSynced {
			// We need to update if any target is synced.
			needsUpdate = true
		}
	}

	if bundle.Status.Target == nil || !apiequality.Semantic.DeepEqual(*bundle.Status.Target, bundle.Spec.Target) {
		bundle.Status.Target = &bundle.Spec.Target
		needsUpdate = true
	}

	if b.setBundleStatusDefaultCAVersion(&bundle, resolvedBundle.defaultCAPackageStringID) {
		needsUpdate = true
	}

	message := "Successfully synced Bundle to all namespaces"
	if nsSelector := bundle.Spec.Target.NamespaceSelector; nsSelector != nil && nsSelector.MatchLabels != nil {
		message = fmt.Sprintf("Successfully synced Bundle to namespaces with selector [matchLabels:%v]",
			nsSelector.MatchLabels)
	}

	syncedCondition := trustapi.BundleCondition{
		Type:    trustapi.BundleConditionSynced,
		Status:  corev1.ConditionTrue,
		Reason:  "Synced",
		Message: message,
	}

	if !needsUpdate && bundleHasCondition(&bundle, syncedCondition) {
		return ctrl.Result{}, nil
	}

	log.V(2).Info("successfully synced bundle")

	b.setBundleCondition(&bundle, syncedCondition)

	b.recorder.Eventf(&bundle, corev1.EventTypeNormal, "Synced", message)

	return ctrl.Result{}, b.targetDirectClient.Status().Update(ctx, &bundle)
}
