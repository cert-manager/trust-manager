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

package target

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	metav1applyconfig "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/test/dummy"
)

const (
	namespace        = "test-namespace"
	bundleName       = "test-bundle"
	key              = "trust.pem"
	jksKey           = "trust.jks"
	pkcs12Key        = "trust.p12"
	data             = dummy.TestCertificate1
	targetAnnotation = "dummyannotation"
	targetLabel      = "dummylabel"
)

var (
	// The actual encoded data is not relevant for this test. So to avoid additional complexity, we just set dummy values.
	jksData    = []byte("JKS")
	pkcs12Data = []byte("PKCS12")
)

func Test_ApplyTarget_ConfigMap(t *testing.T) {
	bundleHash := TrustBundleHash([]byte(data), nil, nil)

	tests := map[string]struct {
		object runtime.Object
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Add annotation to target metadata
		withTargetAnnotation bool
		// Add label to target metadata
		withTargetLabel bool
		// Expect JKS to exist in the configmap at the end of the sync.
		expJKS bool
		// Expect PKCS12 to exist in the configmap at the end of the sync.
		expPKCS12      bool
		expNeedsUpdate bool
		// Expect configmap to have the target annotation
		expTargetAnnotation bool
		// Expect configmap to have the target label
		expTargetLabel bool
	}{
		"if object doesn't exist, expect update": {
			object:         nil,
			expNeedsUpdate: true,
		},
		"if object doesn't exist with JKS, expect update": {
			object:         nil,
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object doesn't exist with PKCS12, expect update": {
			object:         nil,
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists but without data or owner, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     namespace,
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					ManagedFields: ssa_client.ManagedFieldEntries(nil, nil),
				},
			},
			expNeedsUpdate: true,
		},
		"if object exists with data but no owner, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     namespace,
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but no data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
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
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
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
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: "wrong data"},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but without JKS, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but without PKCS12, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{"wrong key"}, nil),
				},
				BinaryData: map[string][]byte{"wrong key": []byte(data)},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong JKS key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, []string{"wrong key"}),
				},
				BinaryData: map[string][]byte{
					key:         []byte(data),
					"wrong-key": []byte(data),
				},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong PKCS12 key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key, "wrong key"}, nil),
				},
				Data: map[string]string{
					key:         data,
					"wrong-key": data,
				},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with correct data, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			expNeedsUpdate: false,
		},
		"if object exists without JKS, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists without PKCS12, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with correct data and some extra data (not owned by our fieldmanager) and owner, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
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
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{
					key:           data,
					"another-key": "another-data",
				},
			},
			expNeedsUpdate: false,
		},
		"if object exists but without target annotation, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withTargetAnnotation: true,
			expNeedsUpdate:       true,
			expTargetAnnotation:  true,
		},
		"if object exists but without target label, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string]string{key: data},
			},
			withTargetLabel: true,
			expNeedsUpdate:  true,
			expTargetLabel:  true,
		},
	}

	for name, test := range tests {
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

			r := &Reconciler{
				Client: fakeClient,
				Cache:  fakeClient,
				PatchResourceOverwrite: func(ctx context.Context, obj interface{}) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					ConfigMap:         &trustapi.TargetTemplate{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			resolvedBundle := source.BundleData{Data: data, BinaryData: make(map[string][]byte)}
			if test.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
				}
				resolvedBundle.BinaryData[jksKey] = jksData
			}
			if test.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
				}
				resolvedBundle.BinaryData[pkcs12Key] = pkcs12Data
			}
			if test.withTargetAnnotation {
				if spec.Target.ConfigMap.Metadata == nil {
					spec.Target.ConfigMap.Metadata = &trustapi.TargetMetadata{}
				}
				spec.Target.ConfigMap.Metadata.Annotations = map[string]string{targetAnnotation: "true"}
			}
			if test.withTargetLabel {
				if spec.Target.ConfigMap.Metadata == nil {
					spec.Target.ConfigMap.Metadata = &trustapi.TargetMetadata{}
				}
				spec.Target.ConfigMap.Metadata.Labels = map[string]string{targetLabel: "true"}
			}

			_, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := r.ApplyTarget(ctx, Resource{
				Kind:           KindConfigMap,
				NamespacedName: types.NamespacedName{Name: bundleName, Namespace: namespace},
			}, &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       spec,
			}, resolvedBundle)
			assert.NoError(t, err)

			assert.Equalf(t, test.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", test.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				configmap := resourcePatches[0].(*coreapplyconfig.ConfigMapApplyConfiguration)

				assert.Equal(t, data, configmap.Data[key])

				expectedOwnerReference := metav1applyconfig.
					OwnerReference().
					WithAPIVersion(trustapi.SchemeGroupVersion.String()).
					WithKind(trustapi.BundleKind).
					WithName(bundleName).
					WithUID("").
					WithBlockOwnerDeletion(true).
					WithController(true)
				assert.Equal(t, expectedOwnerReference, &configmap.OwnerReferences[0])

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

				if test.expTargetLabel {
					assert.Contains(t, configmap.Labels, targetLabel)
				}
				if test.expTargetAnnotation {
					assert.Contains(t, configmap.Annotations, targetAnnotation)
				}
			}
		})
	}
}

func Test_ApplyTarget_Secret(t *testing.T) {
	bundleHash := TrustBundleHash([]byte(data), nil, nil)

	tests := map[string]struct {
		object runtime.Object
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Expect JKS to exist in the secret at the end of the sync.
		expJKS bool
		// Expect PKCS12 to exist in the secret at the end of the sync.
		expPKCS12      bool
		expNeedsUpdate bool
	}{
		"if object doesn't exist, expect update": {
			object:         nil,
			expNeedsUpdate: true,
		},
		"if object doesn't exist with JKS, expect update": {
			object:         nil,
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object doesn't exist with PKCS12, expect update": {
			object:         nil,
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists but without data or owner, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     namespace,
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					ManagedFields: ssa_client.ManagedFieldEntries(nil, nil),
				},
			},
			expNeedsUpdate: true,
		},
		"if object exists with data but no owner, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:          bundleName,
					Namespace:     namespace,
					Labels:        map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but no data, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
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
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong data, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
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
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte("wrong data")},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but without JKS, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but without PKCS12, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong key, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{"wrong key"}, nil),
				},
				Data: map[string][]byte{"wrong key": []byte(data)},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong JKS key, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, []string{"wrong key"}),
				},
				Data: map[string][]byte{
					key:         []byte(data),
					"wrong-key": []byte(data),
				},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong PKCS12 key, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key, "wrong key"}, nil),
				},
				Data: map[string][]byte{
					key:         []byte(data),
					"wrong-key": []byte(data),
				},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with correct data, expect no update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			expNeedsUpdate: false,
		},
		"if object exists without JKS, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			withJKS:        true,
			expJKS:         true,
			expNeedsUpdate: true,
		},
		"if object exists without PKCS12, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{key: []byte(data)},
			},
			withPKCS12:     true,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with correct data and some extra data (not owned by our fieldmanager) and owner, expect no update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: bundleHash},
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
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, nil),
				},
				Data: map[string][]byte{
					key:           []byte(data),
					"another-key": []byte("another-data"),
				},
			},
			expNeedsUpdate: false,
		},
	}

	for name, test := range tests {
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

			r := &Reconciler{
				Client: fakeClient,
				Cache:  fakeClient,
				PatchResourceOverwrite: func(ctx context.Context, obj interface{}) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					Secret:            &trustapi.TargetTemplate{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			resolvedBundle := source.BundleData{Data: data, BinaryData: make(map[string][]byte)}
			if test.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
				}
				resolvedBundle.BinaryData[jksKey] = jksData
			}
			if test.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
				}
				resolvedBundle.BinaryData[pkcs12Key] = pkcs12Data
			}

			_, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := r.ApplyTarget(ctx, Resource{
				Kind:           KindSecret,
				NamespacedName: types.NamespacedName{Name: bundleName, Namespace: namespace},
			}, &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       spec,
			}, resolvedBundle)
			assert.NoError(t, err)

			assert.Equalf(t, test.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", test.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				secret := resourcePatches[0].(*coreapplyconfig.SecretApplyConfiguration)

				assert.Equal(t, data, string(secret.Data[key]))

				expectedOwnerReference := metav1applyconfig.
					OwnerReference().
					WithAPIVersion(trustapi.SchemeGroupVersion.String()).
					WithKind(trustapi.BundleKind).
					WithName(bundleName).
					WithUID("").
					WithBlockOwnerDeletion(true).
					WithController(true)
				assert.Equal(t, expectedOwnerReference, &secret.OwnerReferences[0])

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

func Test_TrustBundleHash(t *testing.T) {
	type inputArgs struct {
		data              []byte
		additionalFormats *trustapi.AdditionalFormats
		targetTemplate    *trustapi.TargetTemplate
	}
	tests := map[string]struct {
		input      inputArgs
		matches    []inputArgs
		mismatches []inputArgs
	}{
		"empty data": {
			input: inputArgs{data: []byte{}, additionalFormats: nil},
			matches: []inputArgs{
				{data: []byte{}, additionalFormats: nil},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{}},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{}}},
				// NOTE: default passwords are applied by openapi, so the input arguments for the function
				// will never have a password of "". And we don't have to account for it in the test.
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ptr.To("")}}},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{}}},
				// NOTE: default passwords are applied by openapi, so the input arguments for the function
				// will never have a password of "". And we don't have to account for it in the test.
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: ptr.To("")}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: nil},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ptr.To("nonempty")}}},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: ptr.To("nonempty")}}},
			},
		},
		"non-empty data": {
			input: inputArgs{data: []byte("data"), additionalFormats: nil},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: nil},
			},
		},
		"jks password": {
			input: inputArgs{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ptr.To("password")}}},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ptr.To("password")}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ptr.To("wrong")}}},
			},
		},
		"pkcs12 password": {
			input: inputArgs{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: ptr.To("password")}}},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: ptr.To("password")}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: ptr.To("wrong")}}},
			},
		},
		"target metadata": {
			input: inputArgs{
				data:              []byte("data"),
				additionalFormats: &trustapi.AdditionalFormats{},
				targetTemplate: &trustapi.TargetTemplate{
					Metadata: &trustapi.TargetMetadata{
						Annotations: map[string]string{"annotation1": "value1"},
						Labels:      map[string]string{"annotation1": "value1"},
					},
				},
			},
			matches: []inputArgs{
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: &trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
							Labels:      map[string]string{"annotation1": "value1"},
						},
					},
				},
			},
			mismatches: []inputArgs{
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: &trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: &trustapi.TargetMetadata{
							Labels: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: &trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value2"},
							Labels:      map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: &trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
							Labels:      map[string]string{"annotation1": "value2"},
						},
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			inputHash := TrustBundleHash(test.input.data, test.input.additionalFormats, test.input.targetTemplate)
			for _, match := range test.matches {
				matchHash := TrustBundleHash(match.data, match.additionalFormats, match.targetTemplate)
				assert.Equal(t, inputHash, matchHash)
			}

			for _, mismatch := range test.mismatches {
				mismatchHash := TrustBundleHash(mismatch.data, mismatch.additionalFormats, mismatch.targetTemplate)
				assert.NotEqual(t, inputHash, mismatchHash)
			}
		})
	}
}
