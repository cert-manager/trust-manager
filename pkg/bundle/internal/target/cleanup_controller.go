package target

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
)

// targetCleanupController is responsible for cleaning up obsolete bundle target resources.
type targetCleanupController struct {
	*Reconciler

	// Options holds options for the Bundle controller.
	controller.Options
}

// Reconcile is the top level function for the controller,
// and will be called whenever a Bundle event happens.
func (t *targetCleanupController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	bundleObj := &trustapi.Bundle{}
	err := t.Client.Get(ctx, req.NamespacedName, bundleObj)
	if apierrors.IsNotFound(err) || bundleObj.GetDeletionTimestamp() != nil {
		// Bundle doesn't exist or is about to be deleted.
		// Kubernetes garbage collector will delete obsolete bundle targets.
		return ctrl.Result{}, nil
	}
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get %q: %s", req.NamespacedName, err)
	}

	return ctrl.Result{}, t.reconcile(ctx, bundleObj)
}

func (t *targetCleanupController) reconcile(ctx context.Context, bundle *trustapi.Bundle) error {
	targetKinds := []Kind{KindConfigMap}
	if t.Options.SecretTargetsEnabled {
		targetKinds = append(targetKinds, KindSecret)
	}

	// Convert metav1.LabelSelector to labels.Selector
	nsSelector, err := NamespaceSelector(bundle)
	if err != nil {
		return fmt.Errorf("failed to build NamespaceSelector: %w", err)
	}

	for _, kind := range targetKinds {
		var targetTemplate *trustapi.TargetTemplate
		switch kind {
		case KindConfigMap:
			targetTemplate = bundle.Spec.Target.ConfigMap
		case KindSecret:
			targetTemplate = bundle.Spec.Target.Secret
		default:
			return fmt.Errorf("unknown targetType: %s", kind)
		}

		targetList := &metav1.PartialObjectMetadataList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       string(kind),
			},
		}
		err := t.Cache.List(ctx, targetList, &client.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{
				trustapi.BundleLabelKey: bundle.Name,
			}),
		})
		if err != nil {
			return fmt.Errorf("failed to list %ss: %w", kind, err)
		}

		processTarget := func(targetObj *metav1.PartialObjectMetadata) error {
			targetResource := Resource{
				Kind:           kind,
				NamespacedName: client.ObjectKeyFromObject(targetObj),
			}

			if targetObj.GetDeletionTimestamp() != nil {
				// Don't reconcile target for targets that are being deleted.
				return nil
			}
			if !metav1.IsControlledBy(targetObj, bundle) /* #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010 */ {
				// Skipping delete of target not controlled by bundle
				return nil
			}

			if targetTemplate == nil {
				// No targets of this kind should exist
				_, err := t.CleanupTarget(ctx, targetResource, bundle)
				return err
			}
			if !nsSelector.Empty() {
				// Target namespace selector limits target namespaces. We have to check if target namespace matches selector.
				ns := &corev1.Namespace{}
				if err := t.Client.Get(ctx, client.ObjectKey{Name: targetObj.Namespace}, ns); err != nil {
					return fmt.Errorf("failed to get %s namespace: %w", targetObj.Namespace, err)
				}
				if !nsSelector.Matches(labels.Set(ns.Labels)) {
					// Target namespace does not match selector, and should be cleaned.
					_, err := t.CleanupTarget(ctx, targetResource, bundle)
					return err
				}
			}
			return nil
		}

		for _, targetObj := range targetList.Items {
			err := processTarget(&targetObj)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
