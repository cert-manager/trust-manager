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
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// SyncConfigMap syncs the given data to the target ConfigMap in the given namespace.
// The name of the ConfigMap is the same as the Bundle.
// Ensures the ConfigMap is owned by the given Bundle, and the data is up to date.
// Returns true if the ConfigMap has been created or was updated.
func (r *Reconciler) SyncConfigMap(
	ctx context.Context,
	log logr.Logger,
	bundle *trustapi.Bundle,
	name types.NamespacedName,
	resolvedBundle Data,
	shouldExist bool,
) (bool, error) {
	targetObj := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
	}
	err := r.Cache.Get(ctx, name, targetObj)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get ConfigMap %s: %w", name, err)
	}

	// If the ConfigMap is not found, and should not exist, we are done.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the ConfigMap exists, but should not, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// Apply empty patch to remove the key(s).
		configMapPatch := prepareTargetPatch(coreapplyconfig.ConfigMap(name.Name, name.Namespace), *bundle)
		configMap, err := r.patchConfigMap(ctx, configMapPatch)
		if err != nil {
			return false, fmt.Errorf("failed to patch ConfigMap %s: %w", name, err)
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

	// Generated PKCS #12 is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if PKCS #12 matches)
	hashAnnotations := make(map[string]string)
	hashAnnotations[trustapi.BundleHashAnnotationKey] = fmt.Sprintf("%x", sha256.Sum256([]byte(resolvedBundle.Data)))

	configMapData := map[string]string{
		bundleTarget.ConfigMap.Key: resolvedBundle.Data,
	}
	configMapBinData := resolvedBundle.BinaryData

	// If no additional formats are present then
	// no additional annotations will be written into ConfigMap
	if bundle.Spec.Target.AdditionalFormats != nil {
		maps.Copy(hashAnnotations, truststorePasswordAnnotations(bundleTarget.AdditionalFormats))
	}

	// If the ConfigMap doesn't exist, create it.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, KindConfigMap, log, targetObj, bundle, hashAnnotations); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	configMapPatch := prepareTargetPatch(coreapplyconfig.ConfigMap(name.Name, name.Namespace), *bundle).
		WithAnnotations(hashAnnotations).
		WithData(configMapData).
		WithBinaryData(configMapBinData)

	if _, err = r.patchConfigMap(ctx, configMapPatch); err != nil {
		return false, fmt.Errorf("failed to patch ConfigMap %s: %w", name, err)
	}

	log.V(2).Info("synced bundle to namespace for target ConfigMap")

	return true, nil
}

// SyncSecret syncs the given data to the target Secret in the given namespace.
// The name of the Secret is the same as the Bundle.
// Ensures the Secret is owned by the given Bundle, and the data is up to date.
// Returns true if the Secret has been created or was updated.
func (r *Reconciler) SyncSecret(
	ctx context.Context,
	log logr.Logger,
	bundle *trustapi.Bundle,
	name types.NamespacedName,
	resolvedBundle Data,
	shouldExist bool,
) (bool, error) {
	targetObj := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
	}
	err := r.Cache.Get(ctx, name, targetObj)
	if err != nil && !apierrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get Secret %s: %w", name, err)
	}

	// If the Secret is not found, and should not exist, we are done.
	if apierrors.IsNotFound(err) && !shouldExist {
		return false, nil
	}

	// If the Secret exists, but should not, delete it.
	if !apierrors.IsNotFound(err) && !shouldExist {
		// Apply empty patch to remove the key(s).
		patch := prepareTargetPatch(coreapplyconfig.Secret(name.Name, name.Namespace), *bundle)
		secret, err := r.patchSecret(ctx, patch)
		if err != nil {
			return false, fmt.Errorf("failed to patch Secret %s: %w", name, err)
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

	// Generated PKCS #12 is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if PKCS #12 matches)
	hashAnnotations := make(map[string]string)
	hashAnnotations[trustapi.BundleHashAnnotationKey] = fmt.Sprintf("%x", sha256.Sum256([]byte(resolvedBundle.Data)))

	secretData := map[string][]byte{
		bundleTarget.Secret.Key: []byte(resolvedBundle.Data),
	}

	for k, v := range resolvedBundle.BinaryData {
		secretData[k] = v
	}

	// If no additional formats are present then
	// no additional annotations will be written into ConfigMap
	if bundle.Spec.Target.AdditionalFormats != nil {
		maps.Copy(hashAnnotations, truststorePasswordAnnotations(bundleTarget.AdditionalFormats))
	}

	// If the Secret doesn't exist, create it.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(ctx, KindSecret, log, targetObj, bundle, hashAnnotations); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	secretPatch := prepareTargetPatch(coreapplyconfig.Secret(name.Name, name.Namespace), *bundle).
		WithAnnotations(hashAnnotations).
		WithData(secretData)

	if _, err = r.patchSecret(ctx, secretPatch); err != nil {
		return false, fmt.Errorf("failed to patch Secret %s: %w", name, err)
	}

	log.V(2).Info("synced bundle to namespace for target Secret")

	return true, nil
}

type Kind string

const (
	KindConfigMap Kind = "ConfigMap"
	KindSecret    Kind = "Secret"
)

// This function comparing either was data sources or trust stores passwords changed
// based on sources hash and passwords hashes.
// All hashes are stored in Annotations
func (r *Reconciler) needsUpdate(ctx context.Context, kind Kind, log logr.Logger, obj *metav1.PartialObjectMetadata, bundle *trustapi.Bundle, hashAnnotations map[string]string) (bool, error) {
	needsUpdate := false
	if !metav1.IsControlledBy(obj, bundle) {
		needsUpdate = true
	}

	if obj.GetLabels()[trustapi.BundleLabelKey] != bundle.Name {
		needsUpdate = true
	}

	for k, v := range hashAnnotations {
		if obj.GetAnnotations()[k] != v {
			needsUpdate = true
		}
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
					log.V(2).Info("migrated configmap from CSA to SSA")
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

	target, patch, err := ssa_client.GenerateConfigMapPatch(applyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate patch: %w", err)
	}

	return target, r.Client.Patch(ctx, target, patch, ssa_client.FieldManager, client.ForceOwnership)
}

func (r *Reconciler) patchSecret(ctx context.Context, applyConfig *coreapplyconfig.SecretApplyConfiguration) (*corev1.Secret, error) {
	if r.PatchResourceOverwrite != nil {
		return nil, r.PatchResourceOverwrite(ctx, applyConfig)
	}

	target, patch, err := ssa_client.GenerateSecretPatch(applyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to generate patch: %w", err)
	}

	return target, r.Client.Patch(ctx, target, patch, ssa_client.FieldManager, client.ForceOwnership)
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

type Data struct {
	Data       string
	BinaryData map[string][]byte
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
	return nil
}

// Calculate new password hash annotations from the given additional formats
// keys and passwords
func truststorePasswordAnnotations(bundle *trustapi.AdditionalFormats) map[string]string {
	var truststorePasswordAnnotations = make(map[string]string)

	if bundle.JKS != nil && bundle.JKS.Password != nil {
		truststorePasswordAnnotations[trustapi.BundleJksPasswdHashAnnotationKey] = fmt.Sprintf("%x", sha256.Sum256([]byte(*bundle.JKS.Password)))
	}
	if bundle.PKCS12 != nil && bundle.PKCS12.Password != nil {
		truststorePasswordAnnotations[trustapi.BundlePkcs12PasswdHashAnnotationKey] = fmt.Sprintf("%x", sha256.Sum256([]byte(*bundle.PKCS12.Password)))
	}

	return truststorePasswordAnnotations
}
