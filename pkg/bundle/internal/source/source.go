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

package source

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/pkg/util"
)

type NotFoundError struct{ error }

type InvalidPEMError struct{ error }

type InvalidSecretError struct{ error }

// BundleData holds the result of a call to BuildBundle. It contains the resulting PEM-encoded
// certificate data from concatenating all the sources together, binary data for any additional formats and
// any metadata from the sources which needs to be exposed on the Bundle resource's status field.
type BundleData struct {
	CertPool *util.CertPool

	DefaultCAPackageStringID string
}

type BundleBuilder struct {
	client.Reader

	// DefaultPackage holds the loaded 'default' certificate package, if one was specified
	// at startup.
	DefaultPackage *fspkg.Package

	controller.Options

	// Use only CAs certificates
	UseCACertsOnly bool
}

// BuildBundle retrieves and concatenates all source bundle data for this Bundle object.
// Each source data is validated and pruned to ensure that all certificates within are valid.
func (b *BundleBuilder) BuildBundle(ctx context.Context, bundle trustapi.BundleSpec) (BundleData, error) {
	var resolvedBundle BundleData
	var sources = bundle.Sources
	resolvedBundle.CertPool = util.NewCertPool(
		util.WithFilteredExpiredCerts(b.FilterExpiredCerts),
		util.WithCACertsOnly(ptr.Deref(bundle.UseCACertsOnly, false)),
		util.WithLogger(logf.FromContext(ctx).WithName("cert-pool")),
	)

	for _, source := range sources {
		var certSource bundleSource

		switch {
		case source.ConfigMap != nil:
			certSource = &configMapBundleSource{b.Reader, b.Namespace, source.ConfigMap}

		case source.Secret != nil:
			certSource = &secretBundleSource{b.Reader, b.Namespace, source.Secret}

		case source.InLine != nil:
			certSource = &inlineBundleSource{*source.InLine}

		case source.UseDefaultCAs != nil:
			if !*source.UseDefaultCAs {
				continue
			}
			if b.DefaultPackage == nil {
				return BundleData{}, NotFoundError{fmt.Errorf("no default package was specified when trust-manager was started; default CAs not available")}
			}
			certSource = &defaultCAsBundleSource{b.DefaultPackage.Bundle}
			resolvedBundle.DefaultCAPackageStringID = b.DefaultPackage.StringID()
		default:
			panic(fmt.Sprintf("don't know how to process source: %+v", source))
		}

		if err := certSource.addToCertPool(ctx, resolvedBundle.CertPool); err != nil {
			return BundleData{}, err
		}
	}

	// NB: empty bundles are not valid, so check and return an error if one somehow snuck through.
	if resolvedBundle.CertPool.Size() == 0 {
		return BundleData{}, NotFoundError{fmt.Errorf("couldn't find any valid certificates in bundle")}
	}

	return resolvedBundle, nil
}

type bundleSource interface {
	addToCertPool(context.Context, *util.CertPool) error
}

type inlineBundleSource struct {
	pemData string
}

func (s inlineBundleSource) addToCertPool(_ context.Context, pool *util.CertPool) error {
	if err := pool.AddCertsFromPEM([]byte(s.pemData)); err != nil {
		return InvalidPEMError{fmt.Errorf("inline source contains invalid PEM data: %w", err)}
	}
	return nil
}

type defaultCAsBundleSource struct {
	pemData string
}

func (s defaultCAsBundleSource) addToCertPool(_ context.Context, pool *util.CertPool) error {
	if err := pool.AddCertsFromPEM([]byte(s.pemData)); err != nil {
		return InvalidPEMError{fmt.Errorf("default package contains invalid PEM data: %w", err)}
	}
	return nil
}

type configMapBundleSource struct {
	client.Reader
	Namespace string
	ref       *trustapi.SourceObjectKeySelector
}

func (b configMapBundleSource) addToCertPool(ctx context.Context, pool *util.CertPool) error {
	// this slice will contain a single ConfigMap if we fetch by name
	// or potentially multiple ConfigMaps if we fetch by label selector
	var configMaps []corev1.ConfigMap

	// if Name is set, we `Get` by name
	if b.ref.Name != "" {
		cm := corev1.ConfigMap{}
		if err := b.Get(ctx, client.ObjectKey{
			Namespace: b.Namespace,
			Name:      b.ref.Name,
		}, &cm); err != nil {
			err = fmt.Errorf("failed to get ConfigMap %s/%s: %w", b.Namespace, b.ref.Name, err)
			if apierrors.IsNotFound(err) {
				err = NotFoundError{err}
			}
			return err
		}

		configMaps = []corev1.ConfigMap{cm}
	} else {
		// if Selector is set, we `List` by label selector
		cml := corev1.ConfigMapList{}
		selector, selectorErr := metav1.LabelSelectorAsSelector(b.ref.Selector)
		if selectorErr != nil {
			return fmt.Errorf("failed to parse label selector as Selector for ConfigMap in namespace %s: %w", b.Namespace, selectorErr)
		}
		if err := b.List(ctx, &cml, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return fmt.Errorf("failed to get ConfigMapList: %w", err)
		} else if len(cml.Items) == 0 {
			logf.FromContext(ctx).Info(fmt.Sprintf("label selector %s for ConfigMap didn't match any resources", selector.String()))
			return nil
		}

		configMaps = cml.Items
	}

	for _, cm := range configMaps {
		if len(b.ref.Key) > 0 {
			data, ok := cm.Data[b.ref.Key]
			if !ok {
				return NotFoundError{fmt.Errorf("no data found in ConfigMap %s/%s at key %q", cm.Namespace, cm.Name, b.ref.Key)}
			}
			if err := pool.AddCertsFromPEM([]byte(data)); err != nil {
				return InvalidPEMError{fmt.Errorf("invalid PEM data in ConfigMap %s/%s at key %q: %w", cm.Namespace, cm.Name, b.ref.Key, err)}
			}
		} else if b.ref.IncludeAllKeys {
			for key, data := range cm.Data {
				if err := pool.AddCertsFromPEM([]byte(data)); err != nil {
					return InvalidPEMError{fmt.Errorf("invalid PEM data in ConfigMap %s/%s at key %q: %w", cm.Namespace, cm.Name, key, err)}
				}
			}
		}
	}
	return nil
}

type secretBundleSource struct {
	client.Reader
	Namespace string
	ref       *trustapi.SourceObjectKeySelector
}

func (b secretBundleSource) addToCertPool(ctx context.Context, pool *util.CertPool) error {
	// this slice will contain a single Secret if we fetch by name
	// or potentially multiple Secrets if we fetch by label selector
	var secrets []corev1.Secret

	// if Name is set, we `Get` by name
	if b.ref.Name != "" {
		s := corev1.Secret{}
		if err := b.Get(ctx, client.ObjectKey{
			Namespace: b.Namespace,
			Name:      b.ref.Name,
		}, &s); err != nil {
			err = fmt.Errorf("failed to get Secret %s/%s: %w", b.Namespace, b.ref.Name, err)
			if apierrors.IsNotFound(err) {
				err = NotFoundError{err}
			}
			return err
		}

		secrets = []corev1.Secret{s}
	} else {
		// if Selector is set, we `List` by label selector
		sl := corev1.SecretList{}
		selector, selectorErr := metav1.LabelSelectorAsSelector(b.ref.Selector)
		if selectorErr != nil {
			return fmt.Errorf("failed to parse label selector as Selector for Secret in namespace %s: %w", b.Namespace, selectorErr)
		}
		if err := b.List(ctx, &sl, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return fmt.Errorf("failed to get SecretList: %w", err)
		} else if len(sl.Items) == 0 {
			logf.FromContext(ctx).Info(fmt.Sprintf("label selector %s for Secret didn't match any resources", selector.String()))
			return nil
		}

		secrets = sl.Items
	}

	for _, secret := range secrets {
		if len(b.ref.Key) > 0 {
			data, ok := secret.Data[b.ref.Key]
			if !ok {
				return NotFoundError{fmt.Errorf("no data found in Secret %s/%s at key %q", secret.Namespace, secret.Name, b.ref.Key)}
			}
			if err := pool.AddCertsFromPEM(data); err != nil {
				return InvalidPEMError{fmt.Errorf("invalid PEM data in Secret %s/%s at key %q: %w", secret.Namespace, secret.Name, b.ref.Key, err)}
			}
		} else if b.ref.IncludeAllKeys {
			// This is done to prevent mistakes. All keys should never be included for a TLS secret, since that would include the private key.
			if secret.Type == corev1.SecretTypeTLS {
				return InvalidSecretError{fmt.Errorf("includeAllKeys is not supported for TLS Secrets such as %s/%s", secret.Namespace, secret.Name)}
			}

			for key, data := range secret.Data {
				if err := pool.AddCertsFromPEM(data); err != nil {
					return InvalidPEMError{fmt.Errorf("invalid PEM data in Secret %s/%s at key %q: %w", secret.Namespace, secret.Name, key, err)}
				}
			}
		}
	}
	return nil
}
