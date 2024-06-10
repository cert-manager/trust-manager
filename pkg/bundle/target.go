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
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/util/csaupgrade"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/fieldpath"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
)

const (
	// crRegressionFieldManager is the field manager that was introduced by a regression in controller-runtime
	// version 0.15.0; fixed in 15.1 and 0.16.0: https://github.com/kubernetes-sigs/controller-runtime/pull/2435
	// trust-manager 0.6.0 was released with this regression in controller-runtime, which means that we have to
	// take extra care when migrating from CSA to SSA.
	crRegressionFieldManager = "Go-http-client"
	fieldManager             = "trust-manager"
)

// syncConfigMapTarget syncs the given data to the target ConfigMap in the given namespace.
// The name of the ConfigMap is the same as the Bundle.
// Ensures the ConfigMap is owned by the given Bundle, and the data is up to date.
// Returns true if the ConfigMap has been created or was updated.
func (b *bundle) syncConfigMapTarget(
	ctx context.Context,
	log logr.Logger,
	bundle *trustapi.Bundle,
	name string,
	namespace string,
	resolvedBundle bundleData,
	shouldExist bool,
) (bool, error) {
	configMap := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
	}
	err := b.targetCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, name, err)
	}

	// If the ConfigMap exists, but the Bundle is being deleted, delete the ConfigMap.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the ConfigMap should not exist, but it does, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// apply empty patch to remove the key
		configMapPatch := coreapplyconfig.
			ConfigMap(name, namespace).
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

		if err = b.patchConfigMapResource(ctx, configMapPatch); err != nil {
			return false, fmt.Errorf("failed to patch ConfigMap %s/%s: %w", namespace, bundle.Name, err)
		}

		return true, nil
	}

	target := bundle.Spec.Target
	if target.ConfigMap == nil {
		return false, errors.New("target not defined")
	}

	// Generated JKS is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if JKS matches)
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(resolvedBundle.data)))
	configmapData := map[string]string{
		target.ConfigMap.Key: resolvedBundle.data,
	}
	configmapBinData := resolvedBundle.binaryData

	// If the ConfigMap doesn't exist, create it.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := b.needsUpdate(ctx, targetKindConfigMap, log, configMap, bundle, dataHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	configMapPatch := coreapplyconfig.
		ConfigMap(name, namespace).
		WithLabels(map[string]string{
			trustapi.BundleLabelKey: bundle.Name,
		}).
		WithAnnotations(map[string]string{
			trustapi.BundleHashAnnotationKey: dataHash,
		}).
		WithOwnerReferences(
			metav1applyconfig.OwnerReference().
				WithAPIVersion(trustapi.SchemeGroupVersion.String()).
				WithKind(trustapi.BundleKind).
				WithName(bundle.GetName()).
				WithUID(bundle.GetUID()).
				WithBlockOwnerDeletion(true).
				WithController(true),
		).
		WithData(configmapData).
		WithBinaryData(configmapBinData)

	if err = b.patchConfigMapResource(ctx, configMapPatch); err != nil {
		return false, fmt.Errorf("failed to patch ConfigMap %s/%s: %w", namespace, bundle.Name, err)
	}

	log.V(2).Info("synced bundle to namespace for target ConfigMap")

	return true, nil
}

// syncSecretTarget syncs the given data to the target Secret in the given namespace.
// The name of the Secret is the same as the Bundle.
// Ensures the Secret is owned by the given Bundle, and the data is up to date.
// Returns true if the Secret has been created or was updated.
func (b *bundle) syncSecretTarget(
	ctx context.Context,
	log logr.Logger,
	bundle *trustapi.Bundle,
	name string,
	namespace string,
	resolvedBundle bundleData,
	shouldExist bool,
) (bool, error) {
	secret := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
	}
	err := b.targetCache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get Secret %s/%s: %w", namespace, name, err)
	}

	// If the target obj exists, but the Bundle is being deleted, delete the Secret.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the Secret should not exist, but it does, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// apply empty patch to remove the key
		secretPatch := coreapplyconfig.
			Secret(name, namespace).
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

		if err = b.patchSecretResource(ctx, secretPatch); err != nil {
			return false, fmt.Errorf("failed to patch secret %s/%s: %w", namespace, bundle.Name, err)
		}

		return true, nil
	}

	target := bundle.Spec.Target
	if target.Secret == nil {
		return false, errors.New("target not defined")
	}

	// Generated JKS is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if JKS matches)
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(resolvedBundle.data)))
	targetData := map[string][]byte{
		target.Secret.Key: []byte(resolvedBundle.data),
	}

	for k, v := range resolvedBundle.binaryData {
		targetData[k] = v
	}

	// If the Secret doesn't exist, create it.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := b.needsUpdate(ctx, targetKindSecret, log, secret, bundle, dataHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	secretPatch := coreapplyconfig.
		Secret(name, namespace).
		WithLabels(map[string]string{
			trustapi.BundleLabelKey: bundle.Name,
		}).
		WithAnnotations(map[string]string{
			trustapi.BundleHashAnnotationKey: dataHash,
		}).
		WithOwnerReferences(
			metav1applyconfig.OwnerReference().
				WithAPIVersion(trustapi.SchemeGroupVersion.String()).
				WithKind(trustapi.BundleKind).
				WithName(bundle.GetName()).
				WithUID(bundle.GetUID()).
				WithBlockOwnerDeletion(true).
				WithController(true),
		).
		WithData(targetData)

	if err = b.patchSecretResource(ctx, secretPatch); err != nil {
		return false, fmt.Errorf("failed to patch Secret %s/%s: %w", namespace, bundle.Name, err)
	}

	log.V(2).Info("synced bundle to namespace for target Secret")

	return true, nil
}

type targetKind string

const (
	targetKindConfigMap targetKind = "ConfigMap"
	targetKindSecret    targetKind = "Secret"
)

func (b *bundle) needsUpdate(ctx context.Context, kind targetKind, log logr.Logger, obj *metav1.PartialObjectMetadata, bundle *trustapi.Bundle, dataHash string) (bool, error) {
	needsUpdate := false
	if !metav1.IsControlledBy(obj, bundle) {
		needsUpdate = true
	}

	if obj.GetLabels()[trustapi.BundleLabelKey] != bundle.Name {
		needsUpdate = true
	}

	if obj.GetAnnotations()[trustapi.BundleHashAnnotationKey] != dataHash {
		needsUpdate = true
	}

	{
		var key string
		var targetFieldNames []string
		switch kind {
		case targetKindConfigMap:
			key = bundle.Spec.Target.ConfigMap.Key
			targetFieldNames = []string{"data", "binaryData"}
		case targetKindSecret:
			key = bundle.Spec.Target.Secret.Key
			targetFieldNames = []string{"data"}
		default:
			return false, fmt.Errorf("unknown targetType: %s", kind)
		}

		properties, err := listManagedProperties(obj, fieldManager, targetFieldNames...)
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

		if kind == targetKindConfigMap {
			if bundle.Spec.Target.ConfigMap != nil {
				// Check if we need to migrate the ConfigMap managed fields to the Apply field operation
				if didMigrate, err := b.migrateConfigMapToApply(ctx, obj); err != nil {
					return false, fmt.Errorf("failed to migrate ConfigMap %s/%s to Apply: %w", obj.Namespace, obj.Name, err)
				} else if didMigrate {
					log.V(2).Info("migrated configmap from CSA to SSA")
					needsUpdate = true
				}
			}
		}
	}
	return needsUpdate, nil
}

func listManagedProperties(configmap *metav1.PartialObjectMetadata, fieldManager string, fieldNames ...string) (sets.Set[string], error) {
	properties := sets.New[string]()

	for _, managedField := range configmap.ManagedFields {
		// If the managed field isn't owned by the cert-manager controller, ignore.
		if managedField.Manager != fieldManager || managedField.FieldsV1 == nil {
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

func (b *bundle) patchConfigMapResource(ctx context.Context, applyConfig *coreapplyconfig.ConfigMapApplyConfiguration) error {
	if b.patchResourceOverwrite != nil {
		return b.patchResourceOverwrite(ctx, applyConfig)
	}

	configMap, patch, err := ssa_client.GenerateConfigMapPatch(applyConfig)
	if err != nil {
		return fmt.Errorf("failed to generate patch: %w", err)
	}

	err = b.client.Patch(ctx, configMap, patch, &client.PatchOptions{
		FieldManager: fieldManager,
		Force:        ptr.To(true),
	})
	if err != nil {
		return err
	}

	// If the configMap is empty, delete it
	if len(configMap.Data) == 0 && len(configMap.BinaryData) == 0 {
		return b.client.Delete(ctx, configMap)
	}

	return nil
}

func (b *bundle) patchSecretResource(ctx context.Context, applyConfig *coreapplyconfig.SecretApplyConfiguration) error {
	if b.patchResourceOverwrite != nil {
		return b.patchResourceOverwrite(ctx, applyConfig)
	}

	secret, patch, err := ssa_client.GenerateSecretPatch(applyConfig)
	if err != nil {
		return fmt.Errorf("failed to generate patch: %w", err)
	}

	err = b.client.Patch(ctx, secret, patch, &client.PatchOptions{
		FieldManager: fieldManager,
		Force:        ptr.To(true),
	})
	if err != nil {
		return err
	}

	// If the secret is empty, delete it
	if len(secret.Data) == 0 {
		return b.client.Delete(ctx, secret)
	}

	return nil
}

// MIGRATION: This is a migration function that migrates the ownership of
// fields from the Update operation to the Apply operation. This is required
// to ensure that the apply operations will also remove fields that were
// created by the Update operation.
func (b *bundle) migrateConfigMapToApply(ctx context.Context, obj client.Object) (bool, error) {
	patch, err := csaupgrade.UpgradeManagedFieldsPatch(obj, sets.New(fieldManager, crRegressionFieldManager), fieldManager)
	if err != nil {
		return false, err
	}
	if patch != nil {
		return true, b.client.Patch(ctx, obj, client.RawPatch(types.JSONPatchType, patch))
	}
	// No work to be done - already upgraded
	return false, nil
}
