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
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"software.sslmate.com/src/go-pkcs12"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"
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
func (b *bundle) buildSourceBundle(ctx context.Context, sources []trustapi.BundleSource, formats *trustapi.AdditionalFormats) (bundleData, error) {
	var resolvedBundle bundleData
	var bundles []string

	for _, source := range sources {
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

	deduplicatedBundles, err := deduplicateAndSortBundles(bundles)
	if err != nil {
		return bundleData{}, err
	}

	if err := resolvedBundle.populateData(deduplicatedBundles, formats); err != nil {
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
		results.Write(data)
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

func (b *bundleData) populateData(bundles []string, formats *trustapi.AdditionalFormats) error {
	b.data = strings.Join(bundles, "\n") + "\n"

	if formats != nil {
		b.binaryData = make(map[string][]byte)

		if formats.JKS != nil {
			encoded, err := jksEncoder{password: *formats.JKS.Password}.encode(b.data)
			if err != nil {
				return fmt.Errorf("failed to encode JKS: %w", err)
			}
			b.binaryData[formats.JKS.Key] = encoded
		}

		if formats.PKCS12 != nil {
			encoded, err := pkcs12Encoder{password: *formats.PKCS12.Password}.encode(b.data)
			if err != nil {
				return fmt.Errorf("failed to encode PKCS12: %w", err)
			}
			b.binaryData[formats.PKCS12.Key] = encoded
		}
	}
	return nil
}

// remove duplicate certificates from bundles and sort certificates by hash
func deduplicateAndSortBundles(bundles []string) ([]string, error) {
	var block *pem.Block

	var certificatesHashes = make(map[[32]byte]string)

	for _, cert := range bundles {
		certBytes := []byte(cert)

		for {
			block, certBytes = pem.Decode(certBytes)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("couldn't decode PEM block containing certificate")
			}

			// calculate hash sum of the given certificate
			hash := sha256.Sum256(block.Bytes)
			// check existence of the hash
			if _, ok := certificatesHashes[hash]; !ok {
				// neew to trim a newline which is added by Encoder
				certificatesHashes[hash] = string(bytes.Trim(pem.EncodeToMemory(block), "\n"))
			}
		}
	}

	var orderedKeys [][32]byte
	for key := range certificatesHashes {
		orderedKeys = append(orderedKeys, key)
	}
	slices.SortFunc(orderedKeys, func(a, b [32]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	var sortedDeduplicatedCerts []string
	for _, key := range orderedKeys {
		sortedDeduplicatedCerts = append(sortedDeduplicatedCerts, certificatesHashes[key])
	}

	return sortedDeduplicatedCerts, nil
}
