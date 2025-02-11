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
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/sets"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/structured-merge-diff/fieldpath"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
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

// Sync syncs the given data to the target resource.
// Ensures the resource is owned by the given Bundle, and the data is up to date.
// Returns true if the resource has been created, updated or deleted.
func (r *Reconciler) Sync(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle Data,
	shouldExist bool,
) (bool, error) {
	switch target.Kind {
	case KindConfigMap:
		return r.syncConfigMap(ctx, target, bundle, resolvedBundle, shouldExist)
	case KindSecret:
		return r.syncSecret(ctx, target, bundle, resolvedBundle, shouldExist)
	default:
		return false, fmt.Errorf("don't know how to sync target of kind: %s", target.Kind)
	}
}

func (r *Reconciler) syncConfigMap(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle Data,
	shouldExist bool,
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

	// If the resource is not found, and should not exist, we are done.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the resource exists, but should not, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// Apply empty patch to remove the key(s).
		patch := prepareTargetPatch(coreapplyconfig.ConfigMap(target.Name, target.Namespace), *bundle)
		configMap, err := r.patchConfigMap(ctx, patch)
		if err != nil {
			return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
		}
		// If the ConfigMap is empty, delete it.
		if configMap != nil && len(configMap.Data) == 0 && len(configMap.BinaryData) == 0 {
			return true, r.Client.Delete(ctx, configMap)
		}
		return true, nil
	}

	bundleTarget := bundle.Spec.Target
	if bundleTarget.ConfigMap == nil {
		return false, errors.New("target not defined")
	}

	data := map[string]string{
		bundleTarget.ConfigMap.Key: resolvedBundle.Data,
	}
	binData := resolvedBundle.BinaryData

	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, target.Kind, targetObj, bundle, resolvedBundle.Hash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	patch := prepareTargetPatch(coreapplyconfig.ConfigMap(target.Name, target.Namespace), *bundle).
		WithAnnotations(map[string]string{
			trustapi.BundleHashAnnotationKey: resolvedBundle.Hash,
		}).
		WithData(data).
		WithBinaryData(binData)

	if _, err = r.patchConfigMap(ctx, patch); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	logf.FromContext(ctx).V(2).Info("synced bundle to namespace")

	return true, nil
}

func (r *Reconciler) syncSecret(
	ctx context.Context,
	target Resource,
	bundle *trustapi.Bundle,
	resolvedBundle Data,
	shouldExist bool,
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

	// If the resource is not found, and should not exist, we are done.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the resource exists, but should not, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// Apply empty patch to remove the key(s).
		patch := prepareTargetPatch(coreapplyconfig.Secret(target.Name, target.Namespace), *bundle)
		secret, err := r.patchSecret(ctx, patch)
		if err != nil {
			return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
		}
		// If the Secret is empty, delete it.
		if secret != nil && len(secret.Data) == 0 {
			return true, r.Client.Delete(ctx, secret)
		}
		return true, nil
	}

	bundleTarget := bundle.Spec.Target
	if bundleTarget.Secret == nil {
		return false, errors.New("target not defined")
	}

	data := map[string][]byte{
		bundleTarget.Secret.Key: []byte(resolvedBundle.Data),
	}

	for k, v := range resolvedBundle.BinaryData {
		data[k] = v
	}

	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, target.Kind, targetObj, bundle, resolvedBundle.Hash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	patch := prepareTargetPatch(coreapplyconfig.Secret(target.Name, target.Namespace), *bundle).
		WithAnnotations(map[string]string{
			trustapi.BundleHashAnnotationKey: resolvedBundle.Hash,
		}).
		WithData(data)

	if _, err = r.patchSecret(ctx, patch); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	logf.FromContext(ctx).V(2).Info("synced bundle to namespace")

	return true, nil
}

type Kind string

const (
	KindConfigMap Kind = "ConfigMap"
	KindSecret    Kind = "Secret"
)

func (r *Reconciler) needsUpdate(ctx context.Context, kind Kind, obj *metav1.PartialObjectMetadata, bundle *trustapi.Bundle, bundleHash string) (bool, error) {
	needsUpdate := false
	if !metav1.IsControlledBy(obj, bundle) {
		needsUpdate = true
	}

	if obj.GetLabels()[trustapi.BundleLabelKey] != bundle.Name {
		needsUpdate = true
	}

	if obj.GetAnnotations()[trustapi.BundleHashAnnotationKey] != bundleHash {
		needsUpdate = true
	}

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
		expectedProperties := sets.New[string](key)
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

func (r *Reconciler) patchConfigMap(ctx context.Context, applyConfig *coreapplyconfig.ConfigMapApplyConfiguration) (*corev1.ConfigMap, error) {
	if r.PatchResourceOverwrite != nil {
		return nil, r.PatchResourceOverwrite(ctx, applyConfig)
	}

	if applyConfig == nil || applyConfig.Name == nil || applyConfig.Namespace == nil {
		panic("target patch must be non-nil and have a name and namespace")
	}

	// This object is used to deduce the name & namespace + unmarshall the return value in
	obj := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *applyConfig.Name,
			Namespace: *applyConfig.Namespace,
		},
	}

	encodedPatch, err := json.Marshal(applyConfig)
	if err != nil {
		return nil, err
	}

	return obj, r.Client.Patch(ctx, obj, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager, client.ForceOwnership)
}

func (r *Reconciler) patchSecret(ctx context.Context, applyConfig *coreapplyconfig.SecretApplyConfiguration) (*corev1.Secret, error) {
	if r.PatchResourceOverwrite != nil {
		return nil, r.PatchResourceOverwrite(ctx, applyConfig)
	}

	if applyConfig == nil || applyConfig.Name == nil || applyConfig.Namespace == nil {
		panic("target patch must be non-nil and have a name and namespace")
	}

	// This object is used to deduce the name & namespace + unmarshall the return value in
	obj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      *applyConfig.Name,
			Namespace: *applyConfig.Namespace,
		},
	}

	encodedPatch, err := json.Marshal(applyConfig)
	if err != nil {
		return nil, err
	}

	return obj, r.Client.Patch(ctx, obj, ssa_client.ApplyPatch{Patch: encodedPatch}, ssa_client.FieldManager, client.ForceOwnership)
}

type targetApplyConfiguration[T any] interface {
	*coreapplyconfig.ConfigMapApplyConfiguration | *coreapplyconfig.SecretApplyConfiguration

	WithLabels(entries map[string]string) T
	WithOwnerReferences(values ...*metav1applyconfig.OwnerReferenceApplyConfiguration) T
}

func prepareTargetPatch[T targetApplyConfiguration[T]](target T, bundle trustapi.Bundle) T {
	return target.
		WithLabels(map[string]string{
			trustapi.BundleLabelKey: bundle.Name,
		}).
		WithOwnerReferences(
			metav1applyconfig.OwnerReference().
				WithAPIVersion(trustapi.SchemeGroupVersion.String()).
				WithKind(trustapi.BundleKind).
				WithName(bundle.GetName()).
				WithUID(bundle.GetUID()).
				WithBlockOwnerDeletion(true).
				WithController(true),
		)
}

type Resource struct {
	Kind Kind
	types.NamespacedName
}

type Data struct {
	Data string

	BinaryData map[string][]byte

	// Hash is used to determine if target resource needs to be updated or is up-to-date.
	// The PKCS#12 format is not deterministic meaning target resources cannot be updated unconditionally.
	Hash string
}

func (b *Data) Populate(pool *util.CertPool, formats *trustapi.AdditionalFormats) error {
	b.Data = pool.PEM()

	if formats != nil {
		b.BinaryData = make(map[string][]byte)

		if formats.JKS != nil {
			encoded, err := truststore.NewJKSEncoder(*formats.JKS.Password).Encode(pool)
			if err != nil {
				return fmt.Errorf("failed to encode JKS: %w", err)
			}
			b.BinaryData[formats.JKS.Key] = encoded
		}

		if formats.PKCS12 != nil {
			encoded, err := truststore.NewPKCS12Encoder(*formats.PKCS12.Password).Encode(pool)
			if err != nil {
				return fmt.Errorf("failed to encode PKCS12: %w", err)
			}
			b.BinaryData[formats.PKCS12.Key] = encoded
		}
	}

	b.Hash = TrustBundleHash([]byte(b.Data), formats)

	return nil
}

func TrustBundleHash(data []byte, additionalFormats *trustapi.AdditionalFormats) string {
	hash := sha256.New()

	_, _ = hash.Write(data)

	if additionalFormats != nil && additionalFormats.JKS != nil && additionalFormats.JKS.Password != nil {
		_, _ = hash.Write([]byte(*additionalFormats.JKS.Password))
	}
	if additionalFormats != nil && additionalFormats.PKCS12 != nil && additionalFormats.PKCS12.Password != nil {
		_, _ = hash.Write([]byte(*additionalFormats.PKCS12.Password))
	}

	hashValue := [32]byte{}
	hash.Sum(hashValue[:0])

	return hex.EncodeToString(hashValue[:])
}
