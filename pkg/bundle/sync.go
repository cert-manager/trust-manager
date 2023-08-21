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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"
)

const (
	// DefaultJKSPassword is the default password that Java uses; it's a Java convention to use this exact password.
	// Since we're not storing anything secret in the JKS files we generate, this password is not a meaningful security measure
	// but seems often to be expected by applications consuming JKS files
	DefaultJKSPassword = "changeit"
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
			if *source.UseDefaultCAs == false {
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
	err := b.sourceLister.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: ref.Name}, &configMap)
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

// secretBundle returns the data in the target Secret within the trust Namespace.
func (b *bundle) secretBundle(ctx context.Context, ref *trustapi.SourceObjectKeySelector) (string, error) {
	var secret corev1.Secret
	err := b.sourceLister.Get(ctx, client.ObjectKey{Namespace: b.Namespace, Name: ref.Name}, &secret)
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

// encodeJKS creates a binary JKS file from the given PEM-encoded trust bundle and password.
// Note that the password is not treated securely; JKS files generally seem to expect a password
// to exist and so we have the option for one.
func encodeJKS(trustBundle string, password []byte) ([]byte, error) {
	remaining := []byte(trustBundle)

	// WithOrderedAliases ensures that trusted certs are added to the JKS file in order,
	// which makes the files appear to be reliably deterministic.
	ks := jks.New(jks.WithOrderedAliases())

	for len(remaining) > 0 {
		var p *pem.Block

		p, remaining = pem.Decode([]byte(remaining))
		if p == nil {
			break
		}

		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("got invalid cert when trying to encode JKS: %w", err)
		}

		alias := jksAlias(c.Raw, c.Subject.String())

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
				Content: p.Bytes,
			},
		})

		if err != nil {
			// this error should never happen if we set jks.Certificate correctly
			return nil, fmt.Errorf("failed to add cert with alias %q to trust store: %w", alias, err)
		}
	}

	buf := &bytes.Buffer{}

	err := ks.Store(buf, password)
	if err != nil {
		return nil, fmt.Errorf("failed to create JKS file: %w", err)
	}

	return buf.Bytes(), nil
}

// jksAlias creates a JKS-safe alias for the given DER-encoded certificate, such that
// any two certificates will have a different aliases unless they're identical in every way.
// This unique alias fixes an issue where we used the Issuer field as an alias, leading to
// different certs being treated as identical.
// The friendlyName is included in the alias as a UX feature when examining JKS files using a
// tool like `keytool`.
func jksAlias(derData []byte, friendlyName string) string {
	certHashBytes := sha256.Sum256(derData)
	certHash := hex.EncodeToString(certHashBytes[:])

	// Since certHash is the part which actually distinguishes between two
	// certificates, put it first so that it won't be truncated if a cert
	// with a really long subject is added. Not sure what the upper limit
	// for length actually is, but it shouldn't matter here.

	return certHash[:8] + "|" + friendlyName
}

// syncTarget syncs the given data to the target ConfigMap in the given namespace.
// The name of the ConfigMap is the same as the Bundle.
// Ensures the ConfigMap is owned by the given Bundle, and the data is up to date.
// Returns true if the ConfigMap has been created or was updated.
func (b *bundle) syncTarget(ctx context.Context, log logr.Logger,
	bundle *trustapi.Bundle,
	namespaceSelector labels.Selector,
	namespace *corev1.Namespace,
	data string,
) (bool, error) {
	target := bundle.Spec.Target
	var binData *[]byte

	if target.ConfigMap == nil {
		return false, errors.New("target not defined")
	}

	matchNamespace := namespaceSelector.Matches(labels.Set(namespace.Labels))

	var configMap corev1.ConfigMap
	err := b.targetDirectClient.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: bundle.Name}, &configMap)

	if target.AdditionalFormats != nil && target.AdditionalFormats.JKS != nil {
		j, err := encodeJKS(data, []byte(DefaultJKSPassword))
		if err != nil {
			return false, err
		}

		binData = &j
	}

	// If the ConfigMap doesn't exist yet, create it.
	if apierrors.IsNotFound(err) {
		// If the namespace doesn't match selector we do nothing since we don't
		// want to create it, and it also doesn't exist.
		if !matchNamespace {
			log.V(4).Info("ignoring namespace as it doesn't match selector", "labels", namespace.Labels)
			return false, nil
		}

		configMap = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:            bundle.Name,
				Namespace:       namespace.Name,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(bundle, trustapi.SchemeGroupVersion.WithKind("Bundle"))},
			},
			Data: map[string]string{
				target.ConfigMap.Key: data,
			},
		}

		if binData != nil {
			configMap.BinaryData = map[string][]byte{
				target.AdditionalFormats.JKS.Key: *binData,
			}
		}

		return true, b.targetDirectClient.Create(ctx, &configMap)
	}

	if err != nil {
		return false, fmt.Errorf("failed to get configmap %s/%s: %w", namespace, bundle.Name, err)
	}

	// Here, the config map exists, but the selector doesn't match the namespace.
	if !matchNamespace {
		// The ConfigMap is owned by this controller- delete it.
		if metav1.IsControlledBy(&configMap, bundle) {
			log.V(2).Info("deleting bundle from Namespace since namespaceSelector does not match")
			return true, b.targetDirectClient.Delete(ctx, &configMap)
		}
		// The ConfigMap isn't owned by us, so we shouldn't delete it. Return that
		// we did nothing.
		b.recorder.Eventf(&configMap, corev1.EventTypeWarning, "NotOwned", "ConfigMap is not owned by trust.cert-manager.io so ignoring")
		return false, nil
	}

	var needsUpdate bool
	// If ConfigMap is missing OwnerReference, add it back.
	if !metav1.IsControlledBy(&configMap, bundle) {
		configMap.OwnerReferences = append(configMap.OwnerReferences, *metav1.NewControllerRef(bundle, trustapi.SchemeGroupVersion.WithKind("Bundle")))
		needsUpdate = true
	}

	needsJKS := false
	if target.AdditionalFormats != nil && target.AdditionalFormats.JKS != nil {
		if _, ok := configMap.BinaryData[target.AdditionalFormats.JKS.Key]; !ok {
			needsJKS = true
		}
	}

	// If PEM not present, or if JKS required and not present, or configmap PEM doesn't match
	// Generated JKS is not deterministic - best we can do here is update if the pem cert has
	// changed (hence not checking if JKS matches)
	if cmdata, ok := configMap.Data[target.ConfigMap.Key]; !ok || needsJKS || cmdata != data {
		if configMap.Data == nil {
			configMap.Data = make(map[string]string)
		}

		configMap.Data[target.ConfigMap.Key] = data
		if binData != nil {
			if configMap.BinaryData == nil {
				configMap.BinaryData = make(map[string][]byte)
			}

			configMap.BinaryData[target.AdditionalFormats.JKS.Key] = *binData
		}

		needsUpdate = true
	}

	// Exit early if no update is needed
	if !needsUpdate {
		return false, nil
	}

	if err := b.targetDirectClient.Update(ctx, &configMap); err != nil {
		return true, fmt.Errorf("failed to update configmap %s/%s with bundle: %w", namespace, bundle.Name, err)
	}

	log.V(2).Info("synced bundle to namespace")

	return true, nil
}
