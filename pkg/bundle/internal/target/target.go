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
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
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
	PatchResourceOverwrite func(ctx context.Context, obj any) error
}

// CleanupTarget ensures the obsolete bundle target is cleanup up.
// It will delete the target resource if it contains no data after removing the bundle data.
// Returns true if the resource has been deleted.
func (r *Reconciler) CleanupTarget(
	ctx context.Context,
	target Resource,
	bundle *trustmanagerapi.ClusterBundle,
) (bool, error) {
	switch target.Kind {
	case KindConfigMap:
		// Apply an empty patch to remove the key(s).
		patch := prepareTargetPatch(coreapplyconfig.ConfigMap(target.Name, target.Namespace), *bundle)
		configMap, err := r.patchConfigMap(ctx, patch)
		if err != nil {
			return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
		}
		// If the ConfigMap is empty, delete it.
		if configMap != nil && len(configMap.Data) == 0 && len(configMap.BinaryData) == 0 {
			return false, client.IgnoreNotFound(r.Client.Delete(ctx, configMap))
		}
	case KindSecret:
		// Apply an empty patch to remove the key(s).
		patch := prepareTargetPatch(coreapplyconfig.Secret(target.Name, target.Namespace), *bundle)
		secret, err := r.patchSecret(ctx, patch)
		if err != nil {
			return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
		}
		// If the Secret is empty, delete it.
		if secret != nil && len(secret.Data) == 0 {
			return true, client.IgnoreNotFound(r.Client.Delete(ctx, secret))
		}
	default:
		return false, fmt.Errorf("don't know how to clean target of kind: %s", target.Kind)
	}

	return false, nil
}

// ApplyTarget applies the bundle data to the target resource.
// Ensures the resource is owned by the given Bundle, and the data is up to date.
// Returns true if the resource has been created or updated.
func (r *Reconciler) ApplyTarget(
	ctx context.Context,
	target Resource,
	bundle *trustmanagerapi.ClusterBundle,
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
	bundle *trustmanagerapi.ClusterBundle,
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
	bundleHash := TrustBundleHash([]byte(bundlePEM), bundleTarget.ConfigMap)
	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(target.Kind, targetObj, bundle, bundleHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	data := map[string]string{}
	for _, keyValue := range bundleTarget.ConfigMap.Data {
		if keyValue.Format == "" || keyValue.Format == trustmanagerapi.BundleFormatPEM {
			data[keyValue.Key] = bundlePEM
		}
	}

	binData, err := binaryData(resolvedBundle.CertPool, bundle.Annotations, bundleTarget.ConfigMap.Data)
	if err != nil {
		return false, err
	}

	patch := prepareTargetPatch(coreapplyconfig.ConfigMap(target.Name, target.Namespace), *bundle).
		WithAnnotations(bundleTarget.ConfigMap.GetAnnotations()).
		WithAnnotations(map[string]string{
			trustmanagerapi.BundleHashAnnotationKey: bundleHash,
		}).
		WithLabels(bundleTarget.ConfigMap.GetLabels()).
		WithData(data).
		WithBinaryData(binData)

	if _, err = r.patchConfigMap(ctx, patch); err != nil {
		return false, fmt.Errorf("failed to patch %s %s: %w", target.Kind, target.NamespacedName, err)
	}

	logf.FromContext(ctx).V(2).Info("applied bundle to namespace")

	return true, nil
}

func (r *Reconciler) applySecret(
	ctx context.Context,
	target Resource,
	bundle *trustmanagerapi.ClusterBundle,
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
	bundleHash := TrustBundleHash([]byte(bundlePEM), bundleTarget.Secret)
	// If the resource exists, check if it is up-to-date.
	if !apierrors.IsNotFound(err) {
		// Exit early if no update is needed
		if exit, err := r.needsUpdate(target.Kind, targetObj, bundle, bundleHash); err != nil {
			return false, err
		} else if !exit {
			return false, nil
		}
	}

	data := map[string][]byte{}
	for _, keyValue := range bundleTarget.Secret.Data {
		if keyValue.Format == "" || keyValue.Format == trustmanagerapi.BundleFormatPEM {
			data[keyValue.Key] = []byte(bundlePEM)
		}
	}

	binData, err := binaryData(resolvedBundle.CertPool, bundle.Annotations, bundleTarget.Secret.Data)
	if err != nil {
		return false, err
	}
	maps.Copy(data, binData)

	patch := prepareTargetPatch(coreapplyconfig.Secret(target.Name, target.Namespace), *bundle).
		WithAnnotations(bundleTarget.Secret.GetAnnotations()).
		WithAnnotations(map[string]string{
			trustmanagerapi.BundleHashAnnotationKey: bundleHash,
		}).
		WithLabels(bundleTarget.Secret.GetLabels()).
		WithData(data)

	if _, err = r.patchSecret(ctx, patch); err != nil {
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

func (r *Reconciler) needsUpdate(kind Kind, obj *metav1.PartialObjectMetadata, bundle *trustmanagerapi.ClusterBundle, bundleHash string) (bool, error) {
	needsUpdate := false ||
		!metav1.IsControlledBy(obj, bundle) ||
		obj.GetLabels()[trustmanagerapi.BundleLabelKey] != bundle.Name ||
		obj.GetAnnotations()[trustmanagerapi.BundleHashAnnotationKey] != bundleHash

	{
		var target *trustmanagerapi.KeyValueTarget
		var targetFieldNames []string
		switch kind {
		case KindConfigMap:
			target = bundle.Spec.Target.ConfigMap
			targetFieldNames = []string{"data", "binaryData"}
		case KindSecret:
			target = bundle.Spec.Target.Secret
			targetFieldNames = []string{"data"}
		default:
			return false, fmt.Errorf("unknown targetType: %s", kind)
		}

		properties, err := listManagedProperties(obj, ssa_client.FieldManager, targetFieldNames...)
		if err != nil {
			return false, fmt.Errorf("failed to list managed properties: %w", err)
		}
		expectedProperties := sets.New[string]()
		for _, keyValue := range target.Data {
			expectedProperties.Insert(keyValue.Key)
		}
		if !properties.Equal(expectedProperties) {
			needsUpdate = true
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

func prepareTargetPatch[T targetApplyConfiguration[T]](target T, bundle trustmanagerapi.ClusterBundle) T {
	return target.
		WithLabels(map[string]string{
			trustmanagerapi.BundleLabelKey: bundle.Name,
		}).
		WithOwnerReferences(
			metav1applyconfig.OwnerReference().
				WithAPIVersion(trustmanagerapi.SchemeGroupVersion.String()).
				WithKind(trustmanagerapi.ClusterBundleKind).
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

func TrustBundleHash(data []byte, target *trustmanagerapi.KeyValueTarget) string {
	hash := sha256.New()

	_, _ = hash.Write(data)

	if target != nil {
		for _, keyValue := range target.Data {
			if keyValue.PKCS12.Password != nil {
				_, _ = hash.Write([]byte(*keyValue.PKCS12.Password))
			}
		}
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

func binaryData(pool *util.CertPool, annotations map[string]string, targetKeys []trustmanagerapi.TargetKeyValue) (binData map[string][]byte, err error) {
	var pkcs12Encoded []byte
	for _, targetKey := range targetKeys {
		if targetKey.Format == trustmanagerapi.BundleFormatPKCS12 {
			var encoded []byte

			switch {
			case targetKey.Key == annotations[trustapi.AnnotationKeyJKSKey]:
				encoded, err = truststore.NewJKSEncoder(*targetKey.PKCS12.Password).Encode(pool)
				if err != nil {
					return nil, fmt.Errorf("failed to encode JKS: %w", err)
				}
			case pkcs12Encoded == nil:
				encoded, err = truststore.NewPKCS12Encoder(*targetKey.PKCS12.Password, targetKey.PKCS12.Profile).Encode(pool)
				if err != nil {
					return nil, fmt.Errorf("failed to encode PKCS12: %w", err)
				}
				pkcs12Encoded = encoded
			default:
				encoded = pkcs12Encoded
			}

			if binData == nil {
				binData = make(map[string][]byte)
			}
			binData[targetKey.Key] = encoded
		}
	}
	return binData, nil
}
