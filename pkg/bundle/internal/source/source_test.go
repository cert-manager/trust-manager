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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func Test_BuildBundle(t *testing.T) {
	tests := map[string]struct {
		sources                     []trustapi.BundleSource
		filterExpired               bool
		objects                     []runtime.Object
		expData                     string
		expError                    bool
		expNotFoundError            bool
		expInvalidSecretSourceError bool
	}{
		"if no sources defined, should return NotFoundError": {
			expError:         true,
			expNotFoundError: true,
		},
		"if single InLine source defined with newlines, should trim and return": {
			sources: []trustapi.BundleSource{
				{InLine: ptr.To(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2 + "\n")},
			},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if single DefaultPackage source defined, should return": {
			sources: []trustapi.BundleSource{{UseDefaultCAs: ptr.To(true)}},
			expData: dummy.JoinCerts(dummy.TestCertificate5),
		},
		"if single ConfigMap source which doesn't exist, return NotFoundError": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
			},
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source whose key doesn't exist, return NotFoundError": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
			},
			objects:          []runtime.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap"}}},
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source referencing single key, return data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if single ConfigMap source including all keys, return data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", IncludeAllKeys: true}},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"cert-1": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2, "cert-2": dummy.TestCertificate3},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3),
		},
		"if single ConfigMap source, return data even when order changes": {
			// Test uses the same data as the previous one but with different order
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate2 + "\n" + dummy.TestCertificate1},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if selects no ConfigMap sources, should return NotFoundError": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Key: "key", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"selects-nothing": "true"}}}},
			},
			expError:         true,
			expNotFoundError: true,
		},
		"if selects at least one ConfigMap source, return data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Key: "key", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"trust-bundle.certs": "includes"}}}},
				{ConfigMap: &trustapi.SourceObjectKeySelector{Key: "key", Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"selects-nothing": "true"}}}},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap", Labels: map[string]string{"trust-bundle.certs": "includes"}},
				Data:       map[string]string{"key": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if selects at least one ConfigMap source including all keys, return data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{IncludeAllKeys: true, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"trust-bundle.certs": "includes"}}}},
			},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Data: map[string]string{
						"cert-1": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2,
						"cert-3": dummy.TestCertificate3,
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap2", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Data: map[string]string{
						"cert-4": dummy.TestCertificate4,
					},
				}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3),
		},
		"if ConfigMap and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
				{InLine: ptr.To(dummy.TestCertificate2)},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if single Secret source exists which doesn't exist, should return not found error": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source whose key doesn't exist, return NotFoundError": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			objects:          []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret"}}},
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source of type TLS including all keys, return InvalidSecretError": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", IncludeAllKeys: true}},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Type:       corev1.SecretTypeTLS,
				Data:       map[string][]byte{"cert-1": []byte(dummy.TestCertificate1), "cert-2": []byte(dummy.TestCertificate2)},
			}},
			expError:                    true,
			expInvalidSecretSourceError: true,
		},
		"if single Secret source referencing single key, return data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2)},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if single Secret source including all keys, return data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", IncludeAllKeys: true}},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"cert-1": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2), "cert-9": []byte(dummy.TestCertificate4)},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4),
		},
		"if Secret and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
				{InLine: ptr.To(dummy.TestCertificate1)},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate2)},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
		},
		"if Secret, ConfigMap and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
				{InLine: ptr.To(dummy.TestCertificate3)},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": dummy.TestCertificate1},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret"},
					Data:       map[string][]byte{"key": []byte(dummy.TestCertificate2)},
				},
			},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3),
		},
		"if source Secret exists, but not ConfigMap, return not found error": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": dummy.TestCertificate1},
				},
			},
			expError:         true,
			expNotFoundError: true,
		},
		"if source ConfigMap exists, but not Secret, return not found error": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", Key: "key"}},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret"},
					Data:       map[string][]byte{"key": []byte(dummy.TestCertificate1)},
				},
			},
			expError:         true,
			expNotFoundError: true,
		},
		"if selects at least one Secret source including all keys, return data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{IncludeAllKeys: true, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"trust-bundle.certs": "includes"}}}},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret1", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Data: map[string][]byte{
						"cert-1": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2),
						"cert-3": []byte(dummy.TestCertificate3),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret2", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Data: map[string][]byte{
						"cert-4": []byte(dummy.TestCertificate4),
					},
				}},
			expData: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate4, dummy.TestCertificate3),
		},
		"if selects at least one Secret source of type TLS including all keys, return InvalidSecretError": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{IncludeAllKeys: true, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"trust-bundle.certs": "includes"}}}},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret1", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Data: map[string][]byte{
						"cert-1": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2),
						"cert-3": []byte(dummy.TestCertificate3),
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret2", Labels: map[string]string{"trust-bundle.certs": "includes"}},
					Type:       corev1.SecretTypeTLS,
					Data: map[string][]byte{
						"cert-4": []byte(dummy.TestCertificate4),
					},
				}},
			expError:                    true,
			expInvalidSecretSourceError: true,
		},
		"if has any non-expired certificate, return data": {
			sources: []trustapi.BundleSource{
				// The first in-line source contains an expired certificate (only)
				{InLine: ptr.To(dummy.TestExpiredCertificate)},
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", Key: "key"}},
			},
			filterExpired: true,
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": dummy.TestCertificate1},
				},
			},
			expData:          dummy.JoinCerts(dummy.TestCertificate1),
			expError:         false,
			expNotFoundError: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fakeClient := fake.NewClientBuilder().
				WithRuntimeObjects(tt.objects...).
				WithScheme(test.Scheme).
				Build()

			b := &BundleBuilder{
				Reader: fakeClient,
				DefaultPackage: &fspkg.Package{
					Name:    "testpkg",
					Version: "123",
					Bundle:  dummy.TestCertificate5,
				},
				Options: controller.Options{FilterExpiredCerts: tt.filterExpired},
			}

			bundle := trustapi.BundleSpec{
				Sources: tt.sources,
			}
			resolvedBundle, err := b.BuildBundle(t.Context(), bundle)

			if (err != nil) != tt.expError {
				t.Errorf("unexpected error, exp=%t got=%v", tt.expError, err)
			}
			if errors.As(err, &NotFoundError{}) != tt.expNotFoundError {
				t.Errorf("unexpected NotFoundError, exp=%t got=%v", tt.expNotFoundError, err)
			}
			if errors.As(err, &InvalidSecretError{}) != tt.expInvalidSecretSourceError {
				t.Errorf("unexpected InvalidSecretError, exp=%t got=%v", tt.expInvalidSecretSourceError, err)
			}

			data := resolvedBundle.CertPool.PEM()
			if data != tt.expData {
				t.Errorf("unexpected data, exp=%q got=%q", tt.expData, data)
			}
		})
	}
}

func TestBundlesDeduplication(t *testing.T) {
	tests := map[string]struct {
		name       string
		bundle     []string
		expError   string
		testBundle []string
	}{
		"single, different cert per source": {
			bundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate2,
			},
			testBundle: []string{
				dummy.TestCertificate2,
				dummy.TestCertificate1,
			},
		},
		"no certs in sources": {
			bundle:     []string{},
			testBundle: nil,
		},
		"single cert in the first source, joined certs in the second source": {
			bundle: []string{
				dummy.TestCertificate1,
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate3),
			},
			testBundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate3,
			},
		},
		"joined certs in the first source, single cert in the second source": {
			bundle: []string{
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate3),
				dummy.TestCertificate1,
			},
			testBundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate3,
			},
		},
		"joined, different certs in the first source; joined,different certs in the second source": {
			bundle: []string{
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
				dummy.JoinCerts(dummy.TestCertificate4, dummy.TestCertificate5),
			},
			testBundle: []string{
				dummy.TestCertificate2,
				dummy.TestCertificate1,
				dummy.TestCertificate4,
				dummy.TestCertificate5,
			},
		},
		"all certs are joined ones and equal ones in all sources": {
			bundle: []string{
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate1),
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate1),
			},
			testBundle: []string{
				dummy.TestCertificate1,
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			certPool := util.NewCertPool()
			err := certPool.AddCertsFromPEM([]byte(strings.Join(test.bundle, "\n")))
			if test.expError != "" {
				assert.Error(t, err, test.expError)
			} else {
				assert.Nil(t, err)
			}

			resultBundle := certPool.PEMSplit()

			// check certificates bundle for duplicated certificates
			assert.Equal(t, test.testBundle, resultBundle)
		})
	}
}
