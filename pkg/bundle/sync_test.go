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
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"testing"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/ptr"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/structured-merge-diff/fieldpath"
	"software.sslmate.com/src/go-pkcs12"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func managedFieldEntries(fields []string, dataFields []string) []metav1.ManagedFieldsEntry {
	fieldset := fieldpath.NewSet()
	for _, property := range fields {
		fieldset.Insert(
			fieldpath.MakePathOrDie("data", property),
		)
	}
	for _, property := range dataFields {
		fieldset.Insert(
			fieldpath.MakePathOrDie("binaryData", property),
		)
	}

	jsonFieldSet, err := fieldset.ToJSON()
	if err != nil {
		panic(err)
	}

	return []metav1.ManagedFieldsEntry{
		{
			Manager:   "trust-manager",
			Operation: metav1.ManagedFieldsOperationApply,
			FieldsV1: &metav1.FieldsV1{
				Raw: jsonFieldSet,
			},
		},
	}
}

func Test_syncTarget(t *testing.T) {
	const (
		bundleName = "test-bundle"
		key        = "trust.pem"
		jksKey     = "trust.jks"
		pkcs12Key  = "trust.p12"
		data       = dummy.TestCertificate1
	)
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))

	tests := map[string]struct {
		object      runtime.Object
		namespace   corev1.Namespace
		shouldExist bool
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Expect the configmap to exist at the end of the sync.
		expExists bool
		// Expect JKS to exist in the configmap at the end of the sync.
		expJKS bool
		// Expect PKCS12 to exist in the configmap at the end of the sync.
		expPKCS12 bool
		expEvent  string
		// Expect the owner reference of the configmap to point to the bundle.
		expOwnerReference bool
		expNeedsUpdate    bool
	}{
		"if object doesn't exist, expect update": {
			object:            nil,
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object doesn't exist with JKS, expect update": {
			object:            nil,
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withJKS:           true,
			expExists:         true,
			expJKS:            true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object doesn't exist with PKCS12, expect update": {
			object:            nil,
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withPKCS12:        true,
			expExists:         true,
			expPKCS12:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists but without data or owner, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     "test-namespace",
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					ManagedFields: managedFieldEntries(nil, nil),
				},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with data but no owner, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     "test-namespace",
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but no data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but wrong data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: "wrong hash"},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: "wrong data"},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but without JKS, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withJKS:           true,
			expExists:         true,
			expJKS:            true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but without PKCS12, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withPKCS12:        true,
			expExists:         true,
			expPKCS12:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but wrong key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{"wrong key"}, nil),
				},
				BinaryData: map[string][]byte{"wrong key": []byte(data)},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but wrong JKS key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, []string{"wrong key"}),
				},
				BinaryData: map[string][]byte{
					key:         []byte(data),
					"wrong-key": []byte(data),
				},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withJKS:           true,
			expExists:         true,
			expJKS:            true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but wrong PKCS12 key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key, "wrong key"}, nil),
				},
				Data: map[string]string{
					key:         data,
					"wrong-key": data,
				},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withPKCS12:        true,
			expExists:         true,
			expPKCS12:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with correct data, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    false,
		},
		"if object exists without JKS, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withJKS:           true,
			expExists:         true,
			expJKS:            true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists without PKCS12, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withPKCS12:        true,
			expExists:         true,
			expPKCS12:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with correct data and some extra data (not owned by our fieldmanager) and owner, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               "another-bundle",
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{
					key:           data,
					"another-key": "another-data",
				},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    false,
		},
		"if object doesn't exist and labels match, expect update": {
			object: nil,
			namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-namespace",
				Labels: map[string]string{"foo": "bar"},
			}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object doesn't exist and labels don't match, don't expect update": {
			object: nil,
			namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-namespace",
				Labels: map[string]string{"bar": "foo"},
			}},
			shouldExist:       false,
			expExists:         false,
			expOwnerReference: true,
			expNeedsUpdate:    false,
		},
		"if object exists with correct data and labels match, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-namespace",
				Labels: map[string]string{"foo": "bar"},
			}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    false,
		},
		"if object exists with correct data but labels don't match, expect deletion": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   "test-namespace",
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-namespace",
				Labels: map[string]string{"bar": "foo"},
			}},
			shouldExist:       false,
			expExists:         false,
			expOwnerReference: false,
			expNeedsUpdate:    true,
		},
		"if object exists and labels don't match, expect empty patch": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     "test-namespace",
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			namespace: corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name:   "test-namespace",
				Labels: map[string]string{"bar": "foo"},
			}},
			shouldExist:       false,
			expExists:         false,
			expOwnerReference: false,
			expNeedsUpdate:    true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(trustapi.GlobalScheme)
			if test.object != nil {
				clientBuilder.WithRuntimeObjects(test.object)
			}

			fakeclient := clientBuilder.Build()
			fakerecorder := record.NewFakeRecorder(1)

			var (
				logMutex        sync.Mutex
				resourcePatches []interface{}
			)

			b := &bundle{
				client:   fakeclient,
				recorder: fakerecorder,
				patchResourceOverwrite: func(ctx context.Context, obj interface{}) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					ConfigMap:         &trustapi.KeySelector{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			if test.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.KeySelector{Key: jksKey}
			}
			if test.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.KeySelector{Key: pkcs12Key}
			}

			needsUpdate, err := b.syncTarget(context.TODO(), klogr.New(), &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       spec,
			}, bundleName, test.namespace.Name, data, test.shouldExist)
			assert.NoError(t, err)

			assert.Equalf(t, test.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", test.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				configmap := resourcePatches[0].(*coreapplyconfig.ConfigMapApplyConfiguration)

				if test.expExists {
					assert.Equal(t, data, configmap.Data[key])
				} else {
					assert.Equal(t, 0, len(configmap.BinaryData))
				}

				expectedOwnerReference := metav1applyconfig.
					OwnerReference().
					WithAPIVersion(trustapi.SchemeGroupVersion.String()).
					WithKind(trustapi.BundleKind).
					WithName(bundleName).
					WithUID("").
					WithBlockOwnerDeletion(true).
					WithController(true)

				if test.expOwnerReference {
					assert.Equal(t, expectedOwnerReference, &configmap.OwnerReferences[0])
				} else {
					assert.NotContains(t, configmap.OwnerReferences, expectedOwnerReference)
				}

				jksData, jksExists := configmap.BinaryData[jksKey]
				assert.Equal(t, test.expJKS, jksExists)

				if test.expJKS {
					reader := bytes.NewReader(jksData)

					ks := jks.New()
					err := ks.Load(reader, []byte(DefaultJKSPassword))
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

				pkcs12Data, pkcs12Exists := configmap.BinaryData[pkcs12Key]
				assert.Equal(t, test.expPKCS12, pkcs12Exists)

				if test.expPKCS12 {
					cas, err := pkcs12.DecodeTrustStore(pkcs12Data, DefaultPKCS12Password)
					assert.Nil(t, err)
					assert.Len(t, cas, 1)

					// Only one certificate block for this test, so we can safely ignore the `remaining` byte array
					p, _ := pem.Decode([]byte(data))
					assert.Equal(t, p.Bytes, cas[0].Raw)
				}
			}

			var event string
			select {
			case event = <-fakerecorder.Events:
			default:
			}
			assert.Equal(t, test.expEvent, event)
		})
	}
}

func Test_buildSourceBundle(t *testing.T) {
	tests := map[string]struct {
		bundle           *trustapi.Bundle
		objects          []runtime.Object
		expData          string
		expError         bool
		expNotFoundError bool
	}{
		"if no sources defined, should return an error": {
			bundle:           &trustapi.Bundle{},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: false,
		},
		"if single InLine source defined with newlines, should trim and return": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{InLine: ptr.To(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2 + "\n\n")},
			}}},
			objects:          []runtime.Object{},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if single DefaultPackage source defined, should return": {
			bundle:           &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{{UseDefaultCAs: ptr.To(true)}}}},
			objects:          []runtime.Object{},
			expData:          dummy.JoinCerts(dummy.TestCertificate5),
			expError:         false,
			expNotFoundError: false,
		},
		"if single ConfigMap source which doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source whose key doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects:          []runtime.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source, return data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1 + "\n" + dummy.TestCertificate2},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if ConfigMap and InLine source, return concatenated data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate2)},
			}}},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": dummy.TestCertificate1},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if single Secret source exists which doesn't exist, should return not found error": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source whose key doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects:          []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source, return data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate1 + "\n" + dummy.TestCertificate2)},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2),
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret and InLine source, return concatenated data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate1)},
			}}},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte(dummy.TestCertificate2)},
			}},
			expData:          dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1),
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret, ConfigmMap and InLine source, return concatenated data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{InLine: ptr.To(dummy.TestCertificate3)},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
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
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
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
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "configmap", KeySelector: trustapi.KeySelector{Key: "key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{Name: "secret", KeySelector: trustapi.KeySelector{Key: "key"}}},
			}}},
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
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fakeclient := fakeclient.NewClientBuilder().
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

			resolvedBundle, err := b.buildSourceBundle(context.TODO(), test.bundle)

			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}
			if errors.As(err, &notFoundError{}) != test.expNotFoundError {
				t.Errorf("unexpected notFoundError, exp=%t got=%v", test.expNotFoundError, err)
			}

			if resolvedBundle.data != test.expData {
				t.Errorf("unexpected data, exp=%q got=%q", test.expData, resolvedBundle.data)
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

	password := []byte(DefaultJKSPassword)

	jksFile, err := jksEncoder{password: password}.encode(bundle)
	if err != nil {
		t.Fatalf("didn't expect an error but got: %s", err)
	}

	reader := bytes.NewReader(jksFile)

	ks := jks.New()

	err = ks.Load(reader, password)
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
