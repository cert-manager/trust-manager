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

package target

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/truststore"
	"github.com/cert-manager/trust-manager/pkg/util"
)

type Reconciler struct {
	// a cache-backed Kubernetes client
	Client client.Client

	// Cache is a cache.Cache that holds cached ConfigMap and Secret
	// resources that are used as targets for Bundles.
	Cache client.Reader

	// PatchResourceOverwrite allows use to override the patchResource function
	// it is used for testing purposes
	PatchResourceOverwrite func(ctx context.Context, obj interface{}) error
}

// CleanupTarget ensures the obsolete bundle target is cleanup up.
// It will delete the target resource if it contains no data after removing the bundle data.
// Returns true if the resource has been deleted.
func (r *Reconciler) CleanupTarget(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
) (bool, error) {
	// Apply an empty obj to remove the key(s).
	obj := prepareTargetPatch(target, *bundle)
	if err := r.patchObj(ctx, obj); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}
	// If the target is empty, delete it.
	if obj.Object["data"] == nil && obj.Object["binaryData"] == nil {
		return true, client.IgnoreNotFound(r.Client.Delete(ctx, obj))
	}

	return false, nil
}

// ApplyTarget applies the bundle data to the target resource.
// Ensures the resource is owned by the given Bundle, and the data is up to date.
// Returns true if the resource has been created or updated.
func (r *Reconciler) ApplyTarget(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle source.BundleData,
) (bool, error) {
	switch target.Kind {
	case KindConfigMap:
		return r.applyConfigMap(ctx, target, bundle, resolvedBundle)
	case KindSecret:
		return r.applySecret(ctx, target, bundle, resolvedBundle)
	default:
		return false, fmt.Errorf("don't know how to apply target of kind: %s", target.Kind)
	}
}

func (r *Reconciler) applyConfigMap(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle source.BundleData,
) (bool, error) {
	targetObj := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       string(target.Kind),
			APIVersion: "v1",
		},
	}
	err := r.Cache.Get(ctx, target.NamespacedName, targetObj)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	bundleTarget := bundle.Spec.Target
	if bundleTarget.ConfigMap == nil {
		return false, errors.New("target not defined")
	}

	bundlePEM := resolvedBundle.CertPool.PEM()
	// Generated PKCS #12 is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if PKCS #12 matches)
	bundleHash := TrustBundleHash([]byte(bundlePEM), bundleTarget.AdditionalFormats, bundleTarget.ConfigMap)
	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, target.Kind, targetObj, bundle, bundleHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	data := map[string]string{
		bundleTarget.ConfigMap.Key: bundlePEM,
	}

	binData, err := binaryData(resolvedBundle.CertPool, bundleTarget.AdditionalFormats)
	if err != nil {
		return false, err
	}

	patch := prepareTargetPatch(target, *bundle)
	if patch.GetAnnotations() == nil {
		patch.SetAnnotations(map[string]string{})
	}
	maps.Copy(patch.GetAnnotations(), bundleTarget.ConfigMap.GetAnnotations())
	patch.GetAnnotations()[trustapi.BundleHashAnnotationKey] = bundleHash
	if patch.GetLabels() == nil {
		patch.SetLabels(map[string]string{})
	}
	maps.Copy(patch.GetLabels(), bundleTarget.ConfigMap.GetLabels())
	patch.Object["data"] = data
	patch.Object["binaryData"] = binData

	if err = r.patchObj(ctx, patch); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	logf.FromContext(ctx).V(2).Info("applied bundle to namespace")

	return true, nil
}

func (r *Reconciler) applySecret(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle source.BundleData,
) (bool, error) {
	targetObj := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       string(target.Kind),
			APIVersion: "v1",
		},
	}
	err := r.Cache.Get(ctx, target.NamespacedName, targetObj)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	bundleTarget := bundle.Spec.Target
	if bundleTarget.Secret == nil {
		return false, errors.New("target not defined")
	}

	bundlePEM := resolvedBundle.CertPool.PEM()
	// Generated PKCS #12 is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if PKCS #12 matches)
	bundleHash := TrustBundleHash([]byte(bundlePEM), bundleTarget.AdditionalFormats, bundleTarget.Secret)
	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, target.Kind, targetObj, bundle, bundleHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	data := map[string][]byte{
		bundleTarget.Secret.Key: []byte(bundlePEM),
	}

	binData, err := binaryData(resolvedBundle.CertPool, bundleTarget.AdditionalFormats)
	if err != nil {
		return false, err
	}
	for k, v := range binData {
		data[k] = v
	}

	patch := prepareTargetPatch(target, *bundle)
	if patch.GetAnnotations() == nil {
		patch.SetAnnotations(map[string]string{})
	}
	maps.Copy(patch.GetAnnotations(), bundleTarget.ConfigMap.GetAnnotations())
	patch.GetAnnotations()[trustapi.BundleHashAnnotationKey] = bundleHash
	if patch.GetLabels() == nil {
		patch.SetLabels(map[string]string{})
	}
	maps.Copy(patch.GetLabels(), bundleTarget.ConfigMap.GetLabels())
	patch.Object["data"] = data

	if err = r.patchObj(ctx, patch); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	logf.FromContext(ctx).V(2).Info("applied bundle to namespace")

	return true, nil
}

type Kind string

const (
	KindConfigMap Kind = "ConfigMap"
	KindSecret    Kind = "Secret"
)

func (r *Reconciler) needsUpdate(ctx context.Context, kind Kind, obj *metav1.PartialObjectMetadata, bundle *trustapi.Bundle, bundleHash string) (bool, error) {
	needsUpdate := false ||
		!metav1.IsControlledBy(obj, bundle) ||
		obj.GetLabels()[trustapi.BundleLabelKey] != bundle.Name ||
		obj.GetAnnotations()[trustapi.BundleHashAnnotationKey] != bundleHash

	{
		var key string
		var targetFieldNames []string
		switch kind {
		case KindConfigMap:
			key = bundle.Spec.Target.ConfigMap.Key
			targetFieldNames = []string{"data", "binaryData"}
		case KindSecret:
			key = bundle.Spec.Target.Secret.Key
			targetFieldNames = []string{"data"}
		default:
			return false, fmt.Errorf("unknown targetType: %s", kind)
		}

		properties, err := listManagedProperties(obj, ssa_client.FieldManager, targetFieldNames...)
		if err != nil {
			return false, fmt.Errorf("failed to list managed properties: %w", err)
		}
		expectedProperties := sets.New(key)
		if bundle.Spec.Target.AdditionalFormats != nil && bundle.Spec.Target.AdditionalFormats.JKS != nil {
			expectedProperties.Insert(bundle.Spec.Target.AdditionalFormats.JKS.Key)
		}
		if bundle.Spec.Target.AdditionalFormats != nil && bundle.Spec.Target.AdditionalFormats.PKCS12 != nil {
			expectedProperties.Insert(bundle.Spec.Target.AdditionalFormats.PKCS12.Key)
		}
		if !properties.Equal(expectedProperties) {
			needsUpdate = true
		}

		if kind == KindConfigMap {
			if bundle.Spec.Target.ConfigMap != nil {
				// Check if we need to migrate the ConfigMap managed fields to the Apply field operation
				if didMigrate, err := ssa_client.MigrateToApply(ctx, r.Client, obj); err != nil {
					return false, fmt.Errorf("failed to migrate ConfigMap %s/%s to Apply: %w", obj.Namespace, obj.Name, err)
				} else if didMigrate {
					logf.FromContext(ctx).V(2).Info("migrated configmap from CSA to SSA")
					needsUpdate = true
				}
			}
		}
	}
	return needsUpdate, nil
}

func listManagedProperties(configmap *metav1.PartialObjectMetadata, fieldManager client.FieldOwner, fieldNames ...string) (sets.Set[string], error) {
	properties := sets.New[string]()

	for _, managedField := range configmap.ManagedFields {
		// If the managed field isn't owned by the cert-manager controller, ignore.
		if managedField.Manager != string(fieldManager) || managedField.FieldsV1 == nil {
			continue
		}

		// Decode the managed field.
		var fieldset fieldpath.Set
		if err := fieldset.FromJSON(bytes.NewReader(managedField.FieldsV1.Raw)); err != nil {
			return nil, err
		}

		for _, fieldName := range fieldNames {
			// Extract the labels and annotations of the managed fields.
			configmapData := fieldset.Children.Descend(fieldpath.PathElement{
				FieldName: ptr.To(fieldName),
			})

			// Gather the properties on the managed fields. Remove the '.'
			// prefix which appears on managed field keys.
			configmapData.Iterate(func(path fieldpath.Path) {
				properties.Insert(strings.TrimPrefix(path.String(), "."))
			})
		}
	}

	return properties, nil
}

func (r *Reconciler) patchObj(ctx context.Context, obj *unstructured.Unstructured) error {
	if r.PatchResourceOverwrite != nil {
		return r.PatchResourceOverwrite(ctx, obj)
	}

	if obj == nil || obj.GetName() == "" || obj.GetNamespace() == "" {
		panic("target patch must be non-nil and have a name and namespace")
	}

	return r.Client.Patch(ctx, obj, client.Apply, ssa_client.FieldManager, client.ForceOwnership)
}

func prepareTargetPatch(resource Resource, bundle trustapi.Bundle) *unstructured.Unstructured {
	patch := &unstructured.Unstructured{}
	patch.SetAPIVersion("v1")
	patch.SetKind(string(resource.Kind))
	patch.SetNamespace(resource.Namespace)
	patch.SetName(resource.Name)
	patch.SetLabels(map[string]string{
		trustapi.BundleLabelKey: bundle.Name,
	})
	patch.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion:         trustapi.SchemeGroupVersion.String(),
		Kind:               trustapi.BundleKind,
		Name:               bundle.GetName(),
		UID:                bundle.GetUID(),
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}})
	return patch

}

type Resource struct {
	Kind Kind
	types.NamespacedName
}

func TrustBundleHash(data []byte, additionalFormats *trustapi.AdditionalFormats, target *trustapi.TargetTemplate) string {
	hash := sha256.New()

	_, _ = hash.Write(data)

	if additionalFormats != nil && additionalFormats.JKS != nil && additionalFormats.JKS.Password != nil {
		_, _ = hash.Write([]byte(*additionalFormats.JKS.Password))
	}
	if additionalFormats != nil && additionalFormats.PKCS12 != nil && additionalFormats.PKCS12.Password != nil {
		_, _ = hash.Write([]byte(*additionalFormats.PKCS12.Password))
	}

	// Add Target annotations and labels to the hash so it becomes aware of changes and triggers an update.
	for k, v := range target.GetAnnotations() {
		_, _ = hash.Write([]byte(k + v))
	}
	for k, v := range target.GetLabels() {
		_, _ = hash.Write([]byte(k + v))
	}

	hashValue := [32]byte{}
	hash.Sum(hashValue[:0])

	return hex.EncodeToString(hashValue[:])
}

func binaryData(pool *util.CertPool, formats *trustapi.AdditionalFormats) (binData map[string][]byte, err error) {
	if formats != nil {
		binData = make(map[string][]byte)

		if formats.JKS != nil {
			encoded, err := truststore.NewJKSEncoder(*formats.JKS.Password).Encode(pool)
			if err != nil {
				return nil, fmt.Errorf("failed to encode JKS: %w", err)
			}
			binData[formats.JKS.Key] = encoded
		}

		if formats.PKCS12 != nil {
			encoded, err := truststore.NewPKCS12Encoder(*formats.PKCS12.Password, formats.PKCS12.Profile).Encode(pool)
			if err != nil {
				return nil, fmt.Errorf("failed to encode PKCS12: %w", err)
			}
			binData[formats.PKCS12.Key] = encoded
		}
	}
	return binData, nil
}
