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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"software.sslmate.com/src/go-pkcs12"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func Test_buildSourceBundle(t *testing.T) {
	tests := map[string]struct {
		sources          []trustapi.BundleSource
		formats          *trustapi.AdditionalFormats
		objects          []runtime.Object
		expData          string
		expError         bool
		expNotFoundError bool
		expJKS           bool
		expPKCS12        bool
		expPassword      *string
	}{
		"if no sources defined, should return an error": {
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: false,
		},
		"if single InLine source defined with newlines, should trim and return": {
			sources: []trustapi.BundleSource{
				{InLine: ptr.To(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2 + "\n\n")},
			},
			objects:          []runtime.Object{},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if single DefaultPackage source defined, should return": {
			sources:          []trustapi.BundleSource{{UseDefaultCAs: ptr.To(true)}},
			objects:          []runtime.Object{},
			expData:          dummy.JoinCerts(dummy.TestCertificate5),
			expError:         false,
			expNotFoundError: false,
		},
		"if single ConfigMap source which doesn't exist, return notFoundError": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source whose key doesn't exist, return notFoundError": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects:          []runtime.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source, return data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if ConfigMap and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate2)},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if single Secret source exists which doesn't exist, should return not found error": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source whose key doesn't exist, return notFoundError": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects:          []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source, return data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2)},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate1)},
			},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate2)},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret, ConfigmMap and InLine source, return concatenated data": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate3)},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
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
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if source Secret exists, but not ConfigMap, return not found error": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": dummy.TestCertificate1},
				},
			},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if source ConfigMap exists, but not Secret, return not found error": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret"},
					Data:       map[string][]byte{"key": []byte(dummy.TestCertificate1)},
				},
			},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if has JKS target, return binaryData with encoded JKS": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			formats: &trustapi.AdditionalFormats{
				JKS: &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
					Password: ptr.To(DefaultJKSPassword),
				},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData: dummy.JoinCerts(dummy.TestCertificate1),
			expJKS:  true,
		},
		"if has JKS target with arbitrary password, return binaryData with encoded JKS": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			formats: &trustapi.AdditionalFormats{
				JKS: &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
					Password: ptr.To("testPasswd123"),
				},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData:     dummy.JoinCerts(dummy.TestCertificate1),
			expJKS:      true,
			expPassword: ptr.To("testPasswd123"),
		},
		"if has PKCS12 target, return binaryData with encoded PKCS12": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			formats: &trustapi.AdditionalFormats{
				PKCS12: &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
					Password: ptr.To(DefaultPKCS12Password),
				},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData:   dummy.JoinCerts(dummy.TestCertificate1),
			expPKCS12: true,
		},
		"if has PKCS12 target with arbitrary password, return binaryData with encoded PKCS12": {
			sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			},
			formats: &trustapi.AdditionalFormats{
				PKCS12: &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
					Password: ptr.To("testPasswd123"),
				},
			},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData:     dummy.JoinCerts(dummy.TestCertificate1),
			expPKCS12:   true,
			expPassword: ptr.To("testPasswd123"),
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fakeclient := fake.NewClientBuilder().
				WithRuntimeObjects(test.objects...).
				WithScheme(trustapi.GlobalScheme).
				Build()

			b := &bundle{
				client: fakeclient,
				defaultPackage: &fspkg.Package{
					Name:    "testpkg",
					Version: "123",
					Bundle:  dummy.TestCertificate5,
				},
			}

			// for corresponding store if arbitrary password is expected then set it instead of default one
			var password string
			if test.expJKS {
				if test.expPassword != nil {
					password = *test.expPassword
				} else {
					password = DefaultJKSPassword
				}
			}
			if test.expPKCS12 {
				if test.expPassword != nil {
					password = *test.expPassword
				} else {
					password = DefaultPKCS12Password
				}
			}

			resolvedBundle, err := b.buildSourceBundle(context.TODO(), test.sources, test.formats)

			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}
			if errors.As(err, &notFoundError{}) != test.expNotFoundError {
				t.Errorf("unexpected notFoundError, exp=%t got=%v", test.expNotFoundError, err)
			}

			if resolvedBundle.data != test.expData {
				t.Errorf("unexpected data, exp=%q got=%q", test.expData, resolvedBundle.data)
			}

			binData, jksExists := resolvedBundle.binaryData[jksKey]
			assert.Equal(t, test.expJKS, jksExists)

			if test.expJKS {
				reader := bytes.NewReader(binData)

				ks := jks.New()

				err := ks.Load(reader, []byte(password))
				assert.Nil(t, err)

				entryNames := ks.Aliases()

				assert.Len(t, entryNames, 1)
				assert.True(t, ks.IsTrustedCertificateEntry(entryNames[0]))

				// Safe to ignore errors here, we've tested that it's present and a TrustedCertificateEntry
				cert, _ := ks.GetTrustedCertificateEntry(entryNames[0])

				// Only one certificate block for this test, so we can safely ignore the `remaining` byte array
				p, _ := pem.Decode([]byte(data))
				assert.Equal(t, p.Bytes, cert.Certificate.Content)
			}

			binData, pkcs12Exists := resolvedBundle.binaryData[pkcs12Key]
			assert.Equal(t, test.expPKCS12, pkcs12Exists)

			if test.expPKCS12 {
				cas, err := pkcs12.DecodeTrustStore(binData, password)
				assert.Nil(t, err)
				assert.Len(t, cas, 1)

				// Only one certificate block for this test, so we can safely ignore the `remaining` byte array
				p, _ := pem.Decode([]byte(data))
				assert.Equal(t, p.Bytes, cas[0].Raw)
			}
		})
	}
}

func Test_encodeJKSAliases(t *testing.T) {
	// IMPORTANT: We use TestCertificate1 and TestCertificate2 here because they're defined
	// to be self-signed and to also use the same Subject, while being different certs.
	// This test ensures that the aliases we create when adding to a JKS file is different under
	// these conditions (where the issuer / subject is identical).
	// Using different dummy certs would allow this test to pass but wouldn't actually test anything useful!
	bundle := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2)

	jksFile, err := jksEncoder{password: DefaultJKSPassword}.encode(bundle)
	if err != nil {
		t.Fatalf("didn't expect an error but got: %s", err)
	}

	reader := bytes.NewReader(jksFile)

	ks := jks.New()

	err = ks.Load(reader, []byte(DefaultJKSPassword))
	if err != nil {
		t.Fatalf("failed to parse generated JKS file: %s", err)
	}

	entryNames := ks.Aliases()

	if len(entryNames) != 2 {
		t.Fatalf("expected two certs in JKS file but got %d", len(entryNames))
	}
}

func Test_certAlias(t *testing.T) {
	// We might not ever rely on aliases being stable, but this test seeks
	// to enforce stability for now. It'll be easy to remove.

	// If this test starts failing after TestCertificate1 is updated, it'll
	// need to be updated with the new alias for the new cert.

	block, _ := pem.Decode([]byte(dummy.TestCertificate1))
	if block == nil {
		t.Fatalf("couldn't parse a PEM block from TestCertificate1")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Dummy certificate TestCertificate1 couldn't be parsed: %s", err)
	}

	alias := certAlias(cert.Raw, cert.Subject.String())

	expectedAlias := "548b988f|CN=cmct-test-root,O=cert-manager"

	if alias != expectedAlias {
		t.Fatalf("expected alias to be %q but got %q", expectedAlias, alias)
	}
}

func TestBundlesDeduplication(t *testing.T) {
	tests := map[string]struct {
		name       string
		bundle     []string
		testBundle []string
	}{
		"single, different cert per source": {
			bundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate2,
			},
			testBundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate2,
			},
		},
		"no certs in sources": {
			bundle:     []string{},
			testBundle: []string{},
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
				dummy.TestCertificate3,
				dummy.TestCertificate1,
			},
		},
		"joined, different certs in the first source; joined,different certs in the second source": {
			bundle: []string{
				dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
				dummy.JoinCerts(dummy.TestCertificate4, dummy.TestCertificate5),
			},
			testBundle: []string{
				dummy.TestCertificate1,
				dummy.TestCertificate2,
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
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resultBundle, err := deduplicateBundles(test.bundle)

			assert.Nil(t, err)

			// check certificates bundle for duplicated certificates
			assert.ElementsMatch(t, test.testBundle, resultBundle)
		})
	}
}
