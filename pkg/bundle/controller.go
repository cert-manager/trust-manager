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
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
)

// AddBundleController will register the Bundle controller with the
// controller-runtime Manager.
// The Bundle controller will reconcile Bundles on Bundle events, as well as
// when any related resource event in the Bundle source and target.
// The controller will only cache metadata for ConfigMaps and Secrets.
func AddBundleController(ctx context.Context, mgr manager.Manager, opts Options) error {
	b := &bundle{
		client:   mgr.GetClient(),
		recorder: mgr.GetEventRecorderFor("bundles"),
		clock:    clock.RealClock{},
		Options:  opts,
	}

	if b.Options.DefaultPackageLocation != "" {
		pkg, err := fspkg.LoadPackageFromFile(b.Options.DefaultPackageLocation)
		if err != nil {
			return fmt.Errorf("must load default package successfully when default package location is set: %w", err)
		}

		b.defaultPackage = &pkg

		b.Options.Log.Info("successfully loaded default package from filesystem", "path", b.Options.DefaultPackageLocation)
	}

	// Only reconcile config maps that match the well known name
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("bundles").

		////// Targets //////

		// Reconcile a Bundle on events against a ConfigMap that it
		// owns. Only cache ConfigMap metadata.
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestForOwner(
			mgr.GetScheme(),
			mgr.GetRESTMapper(),
			&trustapi.Bundle{},
			handler.OnlyControllerOwner(),
		), builder.OnlyMetadata).

		////// Sources //////

		// Reconcile trust.cert-manager.io Bundles
		Watches(&trustapi.Bundle{}, &handler.EnqueueRequestForObject{}).

		// Watch all Namespaces. Cache whole Namespaces to include Phase Status.
		// Reconcile all Bundles on a Namespace change.
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []reconcile.Request {
				// If an error happens here and we do nothing, we run the risk of
				// leaving a Namespace behind when syncing.
				// Exiting error is the safest option, as it will force a resync on
				// all Bundles on start.
				bundleList := b.mustBundleList(ctx)

				var requests []reconcile.Request
				for _, bundle := range bundleList.Items {
					requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: bundle.Name}})
				}

				return requests
			},
		)).

		// Watch ConfigMaps in trust Namespace.
		// Reconcile Bundles who reference a modified source ConfigMap.
		Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []reconcile.Request {
				if obj.GetNamespace() != b.Options.Namespace {
					return nil
				}

				// If an error happens here and we do nothing, we run the risk of
				// having trust Bundles out of sync with this source or target
				// ConfigMap.
				// Exiting error is the safest option, as it will force a resync on
				// all Bundles on start.
				bundleList := b.mustBundleList(ctx)

				var requests []reconcile.Request
				for _, bundle := range bundleList.Items {
					for _, source := range bundle.Spec.Sources {
						if source.ConfigMap == nil {
							continue
						}

						// Bundle references this ConfigMap as a source. Add to request.
						if source.ConfigMap.Name == obj.GetName() {
							requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: bundle.Name}})
							break
						}
					}
				}

				return requests
			},
		)).

		// Watch Secrets in trust Namespace.
		// Reconcile Bundles who reference a modified source Secret.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(
			func(ctx context.Context, obj client.Object) []reconcile.Request {
				if obj.GetNamespace() != b.Options.Namespace {
					return nil
				}

				// If an error happens here and we do nothing, we run the risk of
				// having trust Bundles out of sync with this source Secret.
				// Exiting error is the safest option, as it will force a resync on
				// all Bundles on start.
				bundleList := b.mustBundleList(ctx)

				var requests []reconcile.Request
				for _, bundle := range bundleList.Items {
					for _, source := range bundle.Spec.Sources {
						if source.Secret == nil {
							continue
						}

						// Bundle references this Secret as a source. Add to request.
						if source.Secret.Name == obj.GetName() {
							requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: bundle.Name}})
							break
						}
					}
				}

				return requests
			},
		)).

		// Complete controller.
		Complete(b); err != nil {
		return fmt.Errorf("failed to create Bundle controller: %s", err)
	}

	return nil
}

// mustBundleList will return a BundleList of all Bundles in the cluster. If an
// error occurs, will exit error the program.
func (b *bundle) mustBundleList(ctx context.Context) *trustapi.BundleList {
	var bundleList trustapi.BundleList
	if err := b.client.List(ctx, &bundleList); err != nil {
		b.Log.Error(err, "failed to list all Bundles, exiting error")
		os.Exit(-1)
	}

	return &bundleList
}
