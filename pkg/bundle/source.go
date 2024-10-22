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
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/target"
	"github.com/cert-manager/trust-manager/pkg/util"
)

type notFoundError struct{ error }

type selectsNothingError struct{ error }

type invalidSecretSourceError struct{ error }

// bundleData holds the result of a call to buildSourceBundle. It contains the resulting PEM-encoded
// certificate data from concatenating all the sources together, binary data for any additional formats and
// any metadata from the sources which needs to be exposed on the Bundle resource's status field.
type bundleData struct {
	target.Data

	defaultCAPackageStringID string
}

// buildSourceBundle retrieves and concatenates all source bundle data for this Bundle object.
// Each source data is validated and pruned to ensure that all certificates within are valid, and
// is each bundle is concatenated together with a new line character.
func (b *bundle) buildSourceBundle(ctx context.Context, sources []trustapi.BundleSource, formats *trustapi.AdditionalFormats) (bundleData, error) {
	var resolvedBundle bundleData
	certPool := util.NewCertPool(util.WithFilteredExpiredCerts(b.FilterExpiredCerts))

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

		// A source selector may select no configmaps/secrets, and this is not an error.
		if errors.As(err, &selectsNothingError{}) {
			b.Log.Info(err.Error())
			continue
		}

		if err != nil {
			return bundleData{}, fmt.Errorf("failed to retrieve bundle from source: %w", err)
		}

		if err := certPool.AddCertsFromPEM([]byte(sourceData)); err != nil {
			return bundleData{}, fmt.Errorf("invalid PEM data in source: %w", err)
		}
	}

	// NB: empty bundles are not valid so check and return an error if one somehow snuck through.
	if certPool.Size() == 0 {
		return bundleData{}, fmt.Errorf("couldn't find any valid certificates in bundle")
	}

	if err := resolvedBundle.Data.Populate(certPool, formats); err != nil {
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
		if err := b.client.List(ctx, &cml, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return "", fmt.Errorf("failed to get ConfigMapList: %w", err)
		} else if len(cml.Items) == 0 {
			return "", selectsNothingError{fmt.Errorf("label selector %s for ConfigMap didn't match any resources", selector.String())}
		}

		configMaps = cml.Items
	}

	var results strings.Builder
	for _, cm := range configMaps {
		if len(ref.Key) > 0 {
			data, ok := cm.Data[ref.Key]
			if !ok {
				return "", notFoundError{fmt.Errorf("no data found in ConfigMap %s/%s at key %q", cm.Namespace, cm.Name, ref.Key)}
			}
			results.WriteString(data)
			results.WriteByte('\n')
		} else if ref.IncludeAllKeys {
			for _, data := range cm.Data {
				results.WriteString(data)
				results.WriteByte('\n')
			}
		}
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
		if err := b.client.List(ctx, &sl, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return "", fmt.Errorf("failed to get SecretList: %w", err)
		} else if len(sl.Items) == 0 {
			return "", selectsNothingError{fmt.Errorf("label selector %s for Secret didn't match any resources", selector.String())}
		}

		secrets = sl.Items
	}

	var results strings.Builder
	for _, secret := range secrets {
		if len(ref.Key) > 0 {
			data, ok := secret.Data[ref.Key]
			if !ok {
				return "", notFoundError{fmt.Errorf("no data found in Secret %s/%s at key %q", secret.Namespace, secret.Name, ref.Key)}
			}
			results.Write(data)
			results.WriteByte('\n')
		} else if ref.IncludeAllKeys {
			// This is done to prevent mistakes. All keys should never be included for a TLS secret, since that would include the private key.
			if secret.Type == corev1.SecretTypeTLS {
				return "", invalidSecretSourceError{fmt.Errorf("includeAllKeys is not supported for TLS Secrets such as %s/%s", secret.Namespace, secret.Name)}
			}

			for _, data := range secret.Data {
				results.Write(data)
				results.WriteByte('\n')
			}
		}
	}
	return results.String(), nil
}
