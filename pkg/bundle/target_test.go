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
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/structured-merge-diff/fieldpath"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/test/dummy"
)

const (
	bundleName = "test-bundle"
	key        = "trust.pem"
	jksKey     = "trust.jks"
	pkcs12Key  = "trust.p12"
	data       = dummy.TestCertificate1
)

var (
	// The actual encoded data is not relevant for this test. So to avoid additional complexity, we just set dummy values.
	jksData    = []byte("JKS")
	pkcs12Data = []byte("PKCS12")
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

func Test_syncConfigMapTarget(t *testing.T) {
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
		"if object exists with correct data and some extra data (not owned by our field manager) and owner, expect no update": {
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

			clientBuilder := fake.NewClientBuilder().
				WithScheme(trustapi.GlobalScheme)
			if test.object != nil {
				clientBuilder.WithRuntimeObjects(test.object)
			}

			fakeClient := clientBuilder.Build()

			var (
				logMutex        sync.Mutex
				resourcePatches []interface{}
			)

			b := &bundle{
				client:      fakeClient,
				targetCache: fakeClient,
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
			resolvedBundle := bundleData{data: data, binaryData: make(map[string][]byte)}
			if test.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
				}
				resolvedBundle.binaryData[jksKey] = jksData
			}
			if test.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
				}
				resolvedBundle.binaryData[pkcs12Key] = pkcs12Data
			}

			log, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := b.syncConfigMapTarget(ctx, log, &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       spec,
			}, bundleName, test.namespace.Name, resolvedBundle, test.shouldExist)
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

				binData, jksExists := configmap.BinaryData[jksKey]
				assert.Equal(t, test.expJKS, jksExists)

				if test.expJKS {
					assert.Equal(t, jksData, binData)
				}

				binData, pkcs12Exists := configmap.BinaryData[pkcs12Key]
				assert.Equal(t, test.expPKCS12, pkcs12Exists)

				if test.expPKCS12 {
					assert.Equal(t, pkcs12Data, binData)
				}
			}
		})
	}
}

func Test_syncSecretTarget(t *testing.T) {
	dataHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
	const (
		bundleName = "test-bundle"
		key        = "key"
		data       = dummy.TestCertificate1
	)

	tests := map[string]struct {
		object      runtime.Object
		namespace   corev1.Namespace
		shouldExist bool
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Expect the secret to exist at the end of the sync.
		expExists bool
		// Expect JKS to exist in the secret at the end of the sync.
		expJKS bool
		// Expect PKCS12 to exist in the secret at the end of the sync.
		expPKCS12 bool
		// Expect the owner reference of the secret to point to the bundle.
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
			object: &corev1.Secret{
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
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     "test-namespace",
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but no data, expect update": {
			object: &corev1.Secret{
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte("wrong data")},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but without JKS, expect update": {
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{"wrong key": []byte(data)},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with owner but wrong JKS key, expect update": {
			object: &corev1.Secret{
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
				Data: map[string][]byte{
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{
					key:         []byte(data),
					"wrong-key": []byte(data),
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			expExists:         true,
			expOwnerReference: true,
			expNeedsUpdate:    false,
		},
		"if object exists without JKS, expect update": {
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
			},
			namespace:         corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-namespace"}},
			shouldExist:       true,
			withPKCS12:        true,
			expExists:         true,
			expPKCS12:         true,
			expOwnerReference: true,
			expNeedsUpdate:    true,
		},
		"if object exists with correct data and some extra data (not owned by our field manager) and owner, expect no update": {
			object: &corev1.Secret{
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
				Data: map[string][]byte{
					key:           []byte(data),
					"another-key": []byte("another-data"),
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
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
			object: &corev1.Secret{
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
				Data: map[string][]byte{key: []byte(data)},
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
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     "test-namespace",
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: dataHash},
					ManagedFields: managedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
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

			clientBuilder := fake.NewClientBuilder().
				WithScheme(trustapi.GlobalScheme)
			if test.object != nil {
				clientBuilder.WithRuntimeObjects(test.object)
			}

			fakeClient := clientBuilder.Build()

			var (
				logMutex        sync.Mutex
				resourcePatches []interface{}
			)

			b := &bundle{
				client:      fakeClient,
				targetCache: fakeClient,
				patchResourceOverwrite: func(ctx context.Context, obj interface{}) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					Secret:            &trustapi.KeySelector{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			resolvedBundle := bundleData{data: data, binaryData: make(map[string][]byte)}
			if test.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
				}
				resolvedBundle.binaryData[jksKey] = jksData
			}
			if test.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
				}
				resolvedBundle.binaryData[pkcs12Key] = pkcs12Data
			}

			log, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := b.syncSecretTarget(ctx, log, &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       spec,
			}, bundleName, test.namespace.Name, resolvedBundle, test.shouldExist)
			assert.NoError(t, err)

			assert.Equalf(t, test.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", test.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				secret := resourcePatches[0].(*coreapplyconfig.SecretApplyConfiguration)

				if test.expExists {
					assert.Equal(t, data, string(secret.Data[key]))
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
					assert.Equal(t, expectedOwnerReference, &secret.OwnerReferences[0])
				} else {
					assert.NotContains(t, secret.OwnerReferences, expectedOwnerReference)
				}

				binData, jksExists := secret.Data[jksKey]
				assert.Equal(t, test.expJKS, jksExists)

				if test.expJKS {
					assert.Equal(t, jksData, binData)
				}

				binData, pkcs12Exists := secret.Data[pkcs12Key]
				assert.Equal(t, test.expPKCS12, pkcs12Exists)

				if test.expPKCS12 {
					assert.Equal(t, pkcs12Data, binData)
				}
			}
		})
	}
}
