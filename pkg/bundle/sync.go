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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
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
	// oldFieldManager is the field manager that was used by trust-manager before the migration to the Apply field manager.
	oldFieldManager = "Go-http-client"
	fieldManager    = "trust-manager"
)

type notFoundError struct{ error }

// bundleData holds the result of a call to buildSourceBundle. It contains both the resulting PEM-encoded
// certificate data from concatenating all of the sources together and any metadata from the sources which
// needs to be exposed on the Bundle resource's status field.
type bundleData struct {
	data string

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

		sanitizedBundle, err := util.ValidateAndSanitizePEMBundle([]byte(sourceData))
		if err != nil {
			return bundleData{}, fmt.Errorf("invalid PEM data in source: %w", err)
		}

		bundles = append(bundles, string(sanitizedBundle))
	}

	// NB: empty bundles are not valid so check and return an error if one somehow snuck through.

	if len(bundles) == 0 {
		return bundleData{}, fmt.Errorf("couldn't find any valid certificates in bundle")
	}

	resolvedBundle.data = strings.Join(bundles, "\n") + "\n"

	return resolvedBundle, nil
}

// configMapBundle returns the data in the source ConfigMap within the trust Namespace.
func (b *bundle) configMapBundle(ctx context.Context, ref *trustapi.SourceObjectKeySelector) (string, error) {
	var configMap corev1.ConfigMap
	err := b.client.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: ref.Name}, &configMap)
	if apierrors.IsNotFound(err) {
		return "", notFoundError{err}
	}

	if err != nil {
		return "", fmt.Errorf("failed to get ConfigMap %s/%s: %w", b.Namespace, ref.Name, err)
	}

	data, ok := configMap.Data[ref.Key]
	if !ok {
		return "", notFoundError{fmt.Errorf("no data found in ConfigMap %s/%s at key %q", b.Namespace, ref.Name, ref.Key)}
	}

	return data, nil
}

// secretBundle returns the data in the source Secret within the trust Namespace.
func (b *bundle) secretBundle(ctx context.Context, ref *trustapi.SourceObjectKeySelector) (string, error) {
	var secret corev1.Secret
	err := b.client.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: ref.Name}, &secret)
	if apierrors.IsNotFound(err) {
		return "", notFoundError{err}
	}
	if err != nil {
		return "", fmt.Errorf("failed to get Secret %s/%s: %w", b.Namespace, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return "", notFoundError{fmt.Errorf("no data found in Secret %s/%s at key %q", b.Namespace, ref.Name, ref.Key)}
	}

	return string(data), nil
}

type jksEncoder struct {
	password []byte
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

	err = ks.Store(buf, e.password)
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

	return pkcs12.EncodeTrustStoreEntries(rand.Reader, entries, e.password)
}

// syncTarget syncs the given data to the target ConfigMap in the given namespace.
// The name of the ConfigMap is the same as the Bundle.
// Ensures the ConfigMap is owned by the given Bundle, and the data is up to date.
// Returns true if the ConfigMap has been created or was updated.
func (b *bundle) syncTarget(
	ctx context.Context,
	log logr.Logger,
	bundle *trustapi.Bundle,
	name string,
	namespace string,
	data string,
	shouldExist bool,
) (bool, error) {
	configMap := &metav1.PartialObjectMetadata{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
	}
	err := b.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, configMap)
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

		if err = b.patchResource(ctx, configMapPatch); err != nil {
			return false, fmt.Errorf("failed to patch configMap %s/%s: %w", namespace, bundle.Name, err)
		}

		return true, nil
	}

	target := bundle.Spec.Target
	if target.ConfigMap == nil {
		return false, errors.New("target not defined")
	}

	// Generated JKS is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if JKS matches)
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
	configmapData := map[string]string{
		target.ConfigMap.Key: data,
	}
	configmapBinData := map[string][]byte{}

	if target.AdditionalFormats != nil {
		if target.AdditionalFormats.JKS != nil {
			encoded, err := jksEncoder{password: []byte(DefaultJKSPassword)}.encode(data)
			if err != nil {
				return false, fmt.Errorf("failed to encode JKS: %w", err)
			}

			configmapBinData[target.AdditionalFormats.JKS.Key] = encoded
		}

		if target.AdditionalFormats.PKCS12 != nil {
			encoded, err := pkcs12Encoder{password: DefaultPKCS12Password}.encode(data)
			if err != nil {
				return false, fmt.Errorf("failed to encode PKCS12: %w", err)
			}

			configmapBinData[target.AdditionalFormats.PKCS12.Key] = encoded
		}
	}

	// If the ConfigMap doesn't exist, create it.
	needsPatch := apierrors.IsNotFound(err)
	if !needsPatch {
		if !metav1.IsControlledBy(configMap, bundle) {
			needsPatch = true
		}

		if configMap.Labels[trustapi.BundleLabelKey] != bundle.Name {
			needsPatch = true
		}

		if configMap.Annotations[trustapi.BundleHashAnnotationKey] != dataHash {
			needsPatch = true
		}

		{
			properties, err := listManagedProperties(configMap, fieldManager, "data")
			if err != nil {
				return false, fmt.Errorf("failed to list managed properties: %w", err)
			}

			expectedProperties := sets.New[string](target.ConfigMap.Key)

			if !properties.Equal(expectedProperties) {
				needsPatch = true
			}
		}

		{
			properties, err := listManagedProperties(configMap, fieldManager, "binaryData")
			if err != nil {
				return false, fmt.Errorf("failed to list managed properties: %w", err)
			}

			expectedProperties := sets.New[string]()

			if target.AdditionalFormats != nil && target.AdditionalFormats.JKS != nil {
				expectedProperties.Insert(target.AdditionalFormats.JKS.Key)
			}

			if target.AdditionalFormats != nil && target.AdditionalFormats.PKCS12 != nil {
				expectedProperties.Insert(target.AdditionalFormats.PKCS12.Key)
			}

			if !properties.Equal(expectedProperties) {
				needsPatch = true
			}
		}

		if bundle.Status.Target != nil && bundle.Status.Target.ConfigMap != nil {
			// Check if we need to migrate the ConfigMap managed fields to the Apply field operation
			if didMigrate, err := b.migrateConfigMapToApply(ctx, configMap, bundle.Status.Target.ConfigMap.Key); err != nil {
				return false, fmt.Errorf("failed to migrate ConfigMap %s/%s to Apply: %w", namespace, name, err)
			} else if didMigrate {
				log.V(2).Info("migrated configmap from CSA to SSA")
				needsPatch = true
			}
		}
	}

	// Exit early if no update is needed
	if !needsPatch {
		return false, nil
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

	if err = b.patchResource(ctx, configMapPatch); err != nil {
		return false, fmt.Errorf("failed to patch configMap %s/%s: %w", namespace, bundle.Name, err)
	}

	log.V(2).Info("synced bundle to namespace")

	return true, nil
}

func listManagedProperties(configmap *metav1.PartialObjectMetadata, fieldManager string, fieldName string) (sets.Set[string], error) {
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

	return properties, nil
}

func (b *bundle) patchResource(ctx context.Context, obj interface{}) error {
	if b.patchResourceOverwrite != nil {
		return b.patchResourceOverwrite(ctx, obj)
	}

	applyConfig, ok := obj.(*coreapplyconfig.ConfigMapApplyConfiguration)
	if !ok {
		return fmt.Errorf("expected *coreapplyconfig.ConfigMapApplyConfiguration, got %T", obj)
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

// MIGRATION: This is a migration function that migrates the ownership of
// fields from the Update operation to the Apply operation. This is required
// to ensure that the apply operations will also remove fields that were
// created by the Update operation.
func (b *bundle) migrateConfigMapToApply(ctx context.Context, obj client.Object, key string) (bool, error) {
	// isOldConfigMapManagedFieldsEntry returns a function that checks if the given ManagedFieldsEntry is an old
	// ConfigMap managed fields entry. We use this to check if we need to migrate the ConfigMap managed fields to
	// the Apply field operation.
	// Because oldFieldManager is not unique, we also check that the managed fields contains the data key we know was
	// set by trust-manager (bundle.Status.Target.ConfigMap.Key).
	isOldConfigMapManagedFieldsEntry := func(mf *metav1.ManagedFieldsEntry) bool {
		if mf.Manager != oldFieldManager || mf.Operation != metav1.ManagedFieldsOperationUpdate || mf.Subresource != "" {
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
