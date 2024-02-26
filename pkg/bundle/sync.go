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
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/structured-merge-diff/fieldpath"
	"software.sslmate.com/src/go-pkcs12"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/go-logr/logr"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
)

const (
	// DefaultJKSPassword is the default password that Java uses; it's a Java convention to use this exact password.
	// Since we're not storing anything secret in the JKS files we generate, this password is not a meaningful security measure
	// but seems often to be expected by applications consuming JKS files
	DefaultJKSPassword = "changeit"
	// DefaultPKCS12Password is the empty string, that will create a password-less PKCS12 truststore.
	// Password-less PKCS is the new default Java truststore from Java 18.
	// By password-less, it means the certificates are not encrypted, and it contains no MacData for integrity check.
	DefaultPKCS12Password = ""
)

const (
	// crRegressionFieldManager is the field manager that was introduced by a regression in controller-runtime
	// version 0.15.0; fixed in 15.1 and 0.16.0: https://github.com/kubernetes-sigs/controller-runtime/pull/2435
	// trust-manager 0.6.0 was released with this regression in controller-runtime, which means that we have to
	// take extra care when migrating from CSA to SSA.
	crRegressionFieldManager = "Go-http-client"
	fieldManager             = "trust-manager"
)

type notFoundError struct{ error }

// bundleData holds the result of a call to buildSourceBundle. It contains the resulting PEM-encoded
// certificate data from concatenating all the sources together, binary data for any additional formats and
// any metadata from the sources which needs to be exposed on the Bundle resource's status field.
type bundleData struct {
	data       string
	binaryData map[string][]byte

	defaultCAPackageStringID string
}

// buildSourceBundle retrieves and concatenates all source bundle data for this Bundle object.
// Each source data is validated and pruned to ensure that all certificates within are valid, and
// is each bundle is concatenated together with a new line character.
func (b *bundle) buildSourceBundle(ctx context.Context, bundle *trustapi.Bundle) (bundleData, error) {
	var resolvedBundle bundleData
	var bundles []string

	for _, source := range bundle.Spec.Sources {
		var (
			sourceData string
			err        error
		)

		switch {
		case source.ConfigMap != nil:
			sourceData, err = b.configMapBundle(ctx, source.ConfigMap)

		case source.Secret != nil:
			sourceData, err = b.secretBundle(ctx, source.Secret)

		case source.InLine != nil:
			sourceData = *source.InLine

		case source.UseDefaultCAs != nil:
			if !*source.UseDefaultCAs {
				continue
			}

			if b.defaultPackage == nil {
				err = notFoundError{fmt.Errorf("no default package was specified when trust-manager was started; default CAs not available")}
			} else {
				sourceData = b.defaultPackage.Bundle
				resolvedBundle.defaultCAPackageStringID = b.defaultPackage.StringID()
			}
		}

		if err != nil {
			return bundleData{}, fmt.Errorf("failed to retrieve bundle from source: %w", err)
		}

		opts := util.ValidateAndSanitizeOptions{FilterExpired: b.Options.FilterExpiredCerts}
		sanitizedBundle, err := util.ValidateAndSanitizePEMBundleWithOptions([]byte(sourceData), opts)
		if err != nil {
			return bundleData{}, fmt.Errorf("invalid PEM data in source: %w", err)
		}

		bundles = append(bundles, string(sanitizedBundle))
	}

	// NB: empty bundles are not valid so check and return an error if one somehow snuck through.

	if len(bundles) == 0 {
		return bundleData{}, fmt.Errorf("couldn't find any valid certificates in bundle")
	}

	if err := resolvedBundle.populateData(bundles, bundle.Spec.Target); err != nil {
		return bundleData{}, err
	}

	return resolvedBundle, nil
}

// configMapBundle returns the data in the source ConfigMap within the trust Namespace.
func (b *bundle) configMapBundle(ctx context.Context, ref *trustapi.SourceObjectKeySelector) (string, error) {
	// this slice will contain a single ConfigMap if we fetch by name
	// or potentially multiple ConfigMaps if we fetch by label selector
	var configMaps []corev1.ConfigMap

	// if Name is set, we `Get` by name
	if ref.Name != "" {
		cm := corev1.ConfigMap{}
		if err := b.client.Get(ctx, client.ObjectKey{
			Namespace: b.Namespace,
			Name:      ref.Name,
		}, &cm); apierrors.IsNotFound(err) {
			return "", notFoundError{err}
		} else if err != nil {
			return "", fmt.Errorf("failed to get ConfigMap %s/%s: %w", b.Namespace, ref.Name, err)
		}

		configMaps = []corev1.ConfigMap{cm}
	} else {
		// if Selector is set, we `List` by label selector
		cml := corev1.ConfigMapList{}
		selector, selectorErr := metav1.LabelSelectorAsSelector(ref.Selector)
		if selectorErr != nil {
			return "", fmt.Errorf("failed to parse label selector as Selector for ConfigMap in namespace %s: %w", b.Namespace, selectorErr)
		}
		if err := b.client.List(ctx, &cml, client.MatchingLabelsSelector{Selector: selector}); apierrors.IsNotFound(err) {
			return "", notFoundError{err}
		} else if err != nil {
			return "", fmt.Errorf("failed to get ConfigMapList: %w", err)
		}

		configMaps = cml.Items
	}

	var results strings.Builder
	for _, cm := range configMaps {
		data, ok := cm.Data[ref.Key]
		if !ok {
			return "", notFoundError{fmt.Errorf("no data found in ConfigMap %s/%s at key %q", cm.Namespace, cm.Name, ref.Key)}
		}
		results.WriteString(data)
		results.WriteByte('\n')
	}
	return results.String(), nil
}

// secretBundle returns the data in the source Secret within the trust Namespace.
func (b *bundle) secretBundle(ctx context.Context, ref *trustapi.SourceObjectKeySelector) (string, error) {
	// this slice will contain a single Secret if we fetch by name
	// or potentially multiple Secrets if we fetch by label selector
	var secrets []corev1.Secret

	// if Name is set, we `Get` by name
	if ref.Name != "" {
		s := corev1.Secret{}
		if err := b.client.Get(ctx, client.ObjectKey{
			Namespace: b.Namespace,
			Name:      ref.Name,
		}, &s); apierrors.IsNotFound(err) {
			return "", notFoundError{err}
		} else if err != nil {
			return "", fmt.Errorf("failed to get Secret %s/%s: %w", b.Namespace, ref.Name, err)
		}

		secrets = []corev1.Secret{s}
	} else {
		// if Selector is set, we `List` by label selector
		sl := corev1.SecretList{}
		selector, selectorErr := metav1.LabelSelectorAsSelector(ref.Selector)
		if selectorErr != nil {
			return "", fmt.Errorf("failed to parse label selector as Selector for Secret in namespace %s: %w", b.Namespace, selectorErr)
		}
		if err := b.client.List(ctx, &sl, client.MatchingLabelsSelector{Selector: selector}); apierrors.IsNotFound(err) {
			return "", notFoundError{err}
		} else if err != nil {
			return "", fmt.Errorf("failed to get SecretList: %w", err)
		}

		secrets = sl.Items
	}

	var results strings.Builder
	for _, secret := range secrets {
		data, ok := secret.Data[ref.Key]
		if !ok {
			return "", notFoundError{fmt.Errorf("no data found in Secret %s/%s at key %q", secret.Namespace, secret.Name, ref.Key)}
		}
		results.WriteString(string(data))
		results.WriteByte('\n')
	}
	return results.String(), nil
}

type jksEncoder struct {
	password string
}

// encodeJKS creates a binary JKS file from the given PEM-encoded trust bundle and password.
// Note that the password is not treated securely; JKS files generally seem to expect a password
// to exist and so we have the option for one.
func (e jksEncoder) encode(trustBundle string) ([]byte, error) {
	cas, err := util.DecodeX509CertificateChainBytes([]byte(trustBundle))
	if err != nil {
		return nil, fmt.Errorf("failed to decode trust bundle: %w", err)
	}

	// WithOrderedAliases ensures that trusted certs are added to the JKS file in order,
	// which makes the files appear to be reliably deterministic.
	ks := jks.New(jks.WithOrderedAliases())

	for _, c := range cas {
		alias := certAlias(c.Raw, c.Subject.String())

		// Note on CreationTime:
		// Debian's JKS trust store sets the creation time to match the time that certs are added to the
		// trust store (i.e., it's effectively time.Now() at the instant the file is generated).
		// Using that method would make our JKS files in trust-manager non-deterministic, leaving us with
		// two options if we want to maintain determinism:
		// - Using something from the cert being added (e.g. NotBefore / NotAfter)
		// - Using a fixed time (i.e. unix epoch)
		// We use NotBefore here, arbitrarily.

		err = ks.SetTrustedCertificateEntry(alias, jks.TrustedCertificateEntry{
			CreationTime: c.NotBefore,
			Certificate: jks.Certificate{
				Type:    "X509",
				Content: c.Raw,
			},
		})

		if err != nil {
			// this error should never happen if we set jks.Certificate correctly
			return nil, fmt.Errorf("failed to add cert with alias %q to trust store: %w", alias, err)
		}
	}

	buf := &bytes.Buffer{}

	err = ks.Store(buf, []byte(e.password))
	if err != nil {
		return nil, fmt.Errorf("failed to create JKS file: %w", err)
	}

	return buf.Bytes(), nil
}

// certAlias creates a JKS-safe alias for the given DER-encoded certificate, such that
// any two certificates will have a different aliases unless they're identical in every way.
// This unique alias fixes an issue where we used the Issuer field as an alias, leading to
// different certs being treated as identical.
// The friendlyName is included in the alias as a UX feature when examining JKS files using a
// tool like `keytool`.
func certAlias(derData []byte, friendlyName string) string {
	certHashBytes := sha256.Sum256(derData)
	certHash := hex.EncodeToString(certHashBytes[:])

	// Since certHash is the part which actually distinguishes between two
	// certificates, put it first so that it won't be truncated if a cert
	// with a really long subject is added. Not sure what the upper limit
	// for length actually is, but it shouldn't matter here.

	return certHash[:8] + "|" + friendlyName
}

type pkcs12Encoder struct {
	password string
}

func (e pkcs12Encoder) encode(trustBundle string) ([]byte, error) {
	cas, err := util.DecodeX509CertificateChainBytes([]byte(trustBundle))
	if err != nil {
		return nil, fmt.Errorf("failed to decode trust bundle: %w", err)
	}

	var entries []pkcs12.TrustStoreEntry
	for _, c := range cas {
		entries = append(entries, pkcs12.TrustStoreEntry{
			Cert:         c,
			FriendlyName: certAlias(c.Raw, c.Subject.String()),
		})
	}

	encoder := pkcs12.LegacyRC2

	if e.password == "" {
		encoder = pkcs12.Passwordless
	}

	return encoder.EncodeTrustStoreEntries(entries, e.password)
}

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
				v1.OwnerReference().
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
			v1.OwnerReference().
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
				v1.OwnerReference().
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
			v1.OwnerReference().
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

func (b *bundleData) populateData(bundles []string, target trustapi.BundleTarget) error {
	b.data = strings.Join(bundles, "\n") + "\n"

	if target.AdditionalFormats != nil {
		b.binaryData = make(map[string][]byte)

		if target.AdditionalFormats.JKS != nil {
			encoded, err := jksEncoder{password: *target.AdditionalFormats.JKS.Password}.encode(b.data)
			if err != nil {
				return fmt.Errorf("failed to encode JKS: %w", err)
			}
			b.binaryData[target.AdditionalFormats.JKS.Key] = encoded
		}

		if target.AdditionalFormats.PKCS12 != nil {
			encoded, err := pkcs12Encoder{password: *target.AdditionalFormats.PKCS12.Password}.encode(b.data)
			if err != nil {
				return fmt.Errorf("failed to encode PKCS12: %w", err)
			}
			b.binaryData[target.AdditionalFormats.PKCS12.Key] = encoded
		}
	}
	return nil
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
				if didMigrate, err := b.migrateConfigMapToApply(ctx, obj, bundle.Spec.Target.ConfigMap.Key); err != nil {
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
func (b *bundle) migrateConfigMapToApply(ctx context.Context, obj client.Object, key string) (bool, error) {
	// isOldConfigMapManagedFieldsEntry returns a function that checks if the given ManagedFieldsEntry is an old
	// ConfigMap managed fields entry. We use this to check if we need to migrate the ConfigMap managed fields to
	// the Apply field operation.
	// Because crRegressionFieldManager is not unique, we also check that the managed fields contains the data key we know was
	// set by trust-manager (bundle.Status.Target.ConfigMap.Key).
	isOldConfigMapManagedFieldsEntry := func(mf *metav1.ManagedFieldsEntry) bool {
		if (mf.Manager != fieldManager && mf.Manager != crRegressionFieldManager) ||
			mf.Operation != metav1.ManagedFieldsOperationUpdate ||
			mf.Subresource != "" {
			return false
		}

		if mf.FieldsV1 == nil || mf.FieldsV1.Raw == nil {
			return false
		}

		var fieldset fieldpath.Set
		if err := fieldset.FromJSON(bytes.NewReader(mf.FieldsV1.Raw)); err != nil {
			return false // in case we cannot parse the fieldset, we assume it's not an old target
		}

		return fieldset.Has([]fieldpath.PathElement{
			{
				FieldName: ptr.To("data"),
			},
			{
				FieldName: ptr.To(key),
			},
		})
	}

	needsUpdate := false
	for _, mf := range obj.GetManagedFields() {
		if !isOldConfigMapManagedFieldsEntry(&mf) {
			continue
		}
		needsUpdate = true
	}
	if !needsUpdate {
		return false, nil
	}

	var cm corev1.ConfigMap
	if err := b.directClient.Get(ctx, client.ObjectKeyFromObject(obj), &cm); err != nil {
		return false, err
	}

	managedFields := cm.GetManagedFields()
	for i, mf := range managedFields {
		if !isOldConfigMapManagedFieldsEntry(&mf) {
			continue
		}

		needsUpdate = true
		managedFields[i].Operation = metav1.ManagedFieldsOperationApply
		managedFields[i].Manager = fieldManager
	}

	cm.SetManagedFields(managedFields)
	return true, b.directClient.Update(ctx, &cm)
}
