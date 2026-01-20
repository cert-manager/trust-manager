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
	"bytes"
	"context"
	"encoding/pem"
	"sync"
	"testing"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
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
	"software.sslmate.com/src/go-pkcs12"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test"
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

func Test_ApplyTarget_ConfigMap(t *testing.T) {
	bundleHash := TrustBundleHash([]byte(data), nil)

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
					Labels:        map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:        map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: "wrong hash"},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			clientBuilder := fake.NewClientBuilder().
				WithReturnManagedFields().
				WithScheme(test.Scheme)
			if tt.object != nil {
				clientBuilder.WithRuntimeObjects(tt.object)
			}

			fakeClient := clientBuilder.Build()

			var (
				logMutex        sync.Mutex
				resourcePatches []any
			)

			r := &Reconciler{
				Client: fakeClient,
				Cache:  fakeClient,
				PatchResourceOverwrite: func(ctx context.Context, obj any) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			certPool := util.NewCertPool()
			err := certPool.AddCertsFromPEM([]byte(data))
			assert.NoError(t, err)

			var annotations map[string]string
			spec := trustmanagerapi.BundleSpec{
				Target: trustmanagerapi.BundleTarget{
					ConfigMap: &trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{Key: key}},
					},
				},
			}
			resolvedBundle := source.BundleData{CertPool: certPool}
			if tt.withJKS {
				spec.Target.ConfigMap.Data = append(spec.Target.ConfigMap.Data, trustmanagerapi.TargetKeyValue{
					Key:    jksKey,
					Format: trustmanagerapi.BundleFormatPKCS12,
					PKCS12: trustmanagerapi.PKCS12{Password: ptr.To(trustapi.DefaultJKSPassword)},
				})
				annotations = map[string]string{trustapi.AnnotationKeyJKSKey: jksKey}
			}
			if tt.withPKCS12 {
				spec.Target.ConfigMap.Data = append(spec.Target.ConfigMap.Data, trustmanagerapi.TargetKeyValue{
					Key:    pkcs12Key,
					Format: trustmanagerapi.BundleFormatPKCS12,
					PKCS12: trustmanagerapi.PKCS12{Password: ptr.To(trustmanagerapi.DefaultPKCS12Password)},
				})
			}
			if tt.withTargetAnnotation {
				if spec.Target.ConfigMap.Metadata == nil {
					spec.Target.ConfigMap.Metadata = &trustmanagerapi.TargetMetadata{}
				}
				spec.Target.ConfigMap.Metadata.Annotations = map[string]string{targetAnnotation: "true"}
			}
			if tt.withTargetLabel {
				if spec.Target.ConfigMap.Metadata == nil {
					spec.Target.ConfigMap.Metadata = &trustmanagerapi.TargetMetadata{}
				}
				spec.Target.ConfigMap.Metadata.Labels = map[string]string{targetLabel: "true"}
			}

			_, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := r.ApplyTarget(ctx, Resource{
				Kind:           KindConfigMap,
				NamespacedName: types.NamespacedName{Name: bundleName, Namespace: namespace},
			}, &trustmanagerapi.ClusterBundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName, Annotations: annotations},
				Spec:       spec,
			}, resolvedBundle)
			assert.NoError(t, err)

			assert.Equalf(t, tt.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", tt.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				configmap := resourcePatches[0].(*coreapplyconfig.ConfigMapApplyConfiguration)

				assert.Equal(t, data, configmap.Data[key])

				expectedOwnerReference := metav1applyconfig.
					OwnerReference().
					WithAPIVersion(trustmanagerapi.SchemeGroupVersion.String()).
					WithKind(trustmanagerapi.ClusterBundleKind).
					WithName(bundleName).
					WithUID("").
					WithBlockOwnerDeletion(true).
					WithController(true)
				assert.Equal(t, expectedOwnerReference, &configmap.OwnerReferences[0])

				binData, jksExists := configmap.BinaryData[jksKey]
				assert.Equal(t, tt.expJKS, jksExists)

				if tt.expJKS {
					assertJKSData(t, binData, trustapi.DefaultJKSPassword)
				}

				binData, pkcs12Exists := configmap.BinaryData[pkcs12Key]
				assert.Equal(t, tt.expPKCS12, pkcs12Exists)

				if tt.expPKCS12 {
					assertPKCS12Data(t, binData, trustmanagerapi.DefaultPKCS12Password)
				}

				if tt.expTargetLabel {
					assert.Contains(t, configmap.Labels, targetLabel)
				}
				if tt.expTargetAnnotation {
					assert.Contains(t, configmap.Annotations, targetAnnotation)
				}
			}
		})
	}
}

func Test_ApplyTarget_Secret(t *testing.T) {
	bundleHash := TrustBundleHash([]byte(data), nil)

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
					Labels:        map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:        map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations:   map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: "wrong hash"},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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
					Labels:      map[string]string{trustmanagerapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustmanagerapi.BundleHashAnnotationKey: bundleHash},
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

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			clientBuilder := fake.NewClientBuilder().
				WithReturnManagedFields().
				WithScheme(test.Scheme)
			if tt.object != nil {
				clientBuilder.WithRuntimeObjects(tt.object)
			}

			fakeClient := clientBuilder.Build()

			var (
				logMutex        sync.Mutex
				resourcePatches []any
			)

			r := &Reconciler{
				Client: fakeClient,
				Cache:  fakeClient,
				PatchResourceOverwrite: func(ctx context.Context, obj any) error {
					logMutex.Lock()
					defer logMutex.Unlock()

					resourcePatches = append(resourcePatches, obj)
					return nil
				},
			}

			certPool := util.NewCertPool()
			err := certPool.AddCertsFromPEM([]byte(data))
			assert.NoError(t, err)

			var annotations map[string]string
			spec := trustmanagerapi.BundleSpec{
				Target: trustmanagerapi.BundleTarget{
					Secret: &trustmanagerapi.KeyValueTarget{
						Data: []trustmanagerapi.TargetKeyValue{{Key: key}},
					},
				},
			}
			resolvedBundle := source.BundleData{CertPool: certPool}
			if tt.withJKS {
				spec.Target.Secret.Data = append(spec.Target.Secret.Data, trustmanagerapi.TargetKeyValue{
					Key:    jksKey,
					Format: trustmanagerapi.BundleFormatPKCS12,
					PKCS12: trustmanagerapi.PKCS12{Password: ptr.To(trustapi.DefaultJKSPassword)},
				})
				annotations = map[string]string{trustapi.AnnotationKeyJKSKey: jksKey}
			}
			if tt.withPKCS12 {
				spec.Target.Secret.Data = append(spec.Target.Secret.Data, trustmanagerapi.TargetKeyValue{
					Key:    pkcs12Key,
					Format: trustmanagerapi.BundleFormatPKCS12,
					PKCS12: trustmanagerapi.PKCS12{Password: ptr.To(trustmanagerapi.DefaultPKCS12Password)},
				})
			}

			_, ctx := ktesting.NewTestContext(t)
			needsUpdate, err := r.ApplyTarget(ctx, Resource{
				Kind:           KindSecret,
				NamespacedName: types.NamespacedName{Name: bundleName, Namespace: namespace},
			}, &trustmanagerapi.ClusterBundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName, Annotations: annotations},
				Spec:       spec,
			}, resolvedBundle)
			assert.NoError(t, err)

			assert.Equalf(t, tt.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", tt.expNeedsUpdate, needsUpdate)

			if len(resourcePatches) > 1 {
				t.Fatalf("expected only one patch, got %d", len(resourcePatches))
			}

			if len(resourcePatches) == 1 {
				secret := resourcePatches[0].(*coreapplyconfig.SecretApplyConfiguration)

				assert.Equal(t, data, string(secret.Data[key]))

				expectedOwnerReference := metav1applyconfig.
					OwnerReference().
					WithAPIVersion(trustmanagerapi.SchemeGroupVersion.String()).
					WithKind(trustmanagerapi.ClusterBundleKind).
					WithName(bundleName).
					WithUID("").
					WithBlockOwnerDeletion(true).
					WithController(true)
				assert.Equal(t, expectedOwnerReference, &secret.OwnerReferences[0])

				binData, jksExists := secret.Data[jksKey]
				assert.Equal(t, tt.expJKS, jksExists)

				if tt.expJKS {
					assertJKSData(t, binData, trustapi.DefaultJKSPassword)
				}

				binData, pkcs12Exists := secret.Data[pkcs12Key]
				assert.Equal(t, tt.expPKCS12, pkcs12Exists)

				if tt.expPKCS12 {
					assertPKCS12Data(t, binData, trustmanagerapi.DefaultPKCS12Password)
				}
			}
		})
	}
}

func Test_TrustBundleHash(t *testing.T) {
	type inputArgs struct {
		data   []byte
		target *trustmanagerapi.KeyValueTarget
	}
	tests := map[string]struct {
		input      inputArgs
		matches    []inputArgs
		mismatches []inputArgs
	}{
		"empty data": {
			input: inputArgs{data: []byte{}},
			matches: []inputArgs{
				{data: []byte{}},
				{data: []byte{}, target: &trustmanagerapi.KeyValueTarget{}},
				{data: []byte{}, target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{}}}}},
				// NOTE: default passwords are applied by openapi, so the input arguments for the function
				// will never have a password of "". And we don't have to account for it in the test.
				{data: []byte{}, target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{Password: ptr.To("")}}}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data")},
				{data: []byte{}, target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{Password: ptr.To("nonempty")}}}}},
			},
		},
		"non-empty data": {
			input: inputArgs{data: []byte("data")},
			matches: []inputArgs{
				{data: []byte("data")},
			},
		},
		"pkcs12 password": {
			input: inputArgs{data: []byte("data"), target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{Password: ptr.To("password")}}}}},
			matches: []inputArgs{
				{data: []byte("data"), target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{Password: ptr.To("password")}}}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), target: &trustmanagerapi.KeyValueTarget{Data: []trustmanagerapi.TargetKeyValue{{PKCS12: trustmanagerapi.PKCS12{Password: ptr.To("wrong")}}}}},
			},
		},
		"target metadata": {
			input: inputArgs{
				data: []byte("data"),
				target: &trustmanagerapi.KeyValueTarget{
					Metadata: &trustmanagerapi.TargetMetadata{
						Annotations: map[string]string{"annotation1": "value1"},
						Labels:      map[string]string{"annotation1": "value1"},
					},
				},
			},
			matches: []inputArgs{
				{
					data: []byte("data"),
					target: &trustmanagerapi.KeyValueTarget{
						Metadata: &trustmanagerapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
							Labels:      map[string]string{"annotation1": "value1"},
						},
					},
				},
			},
			mismatches: []inputArgs{
				{
					data: []byte("data"),
					target: &trustmanagerapi.KeyValueTarget{
						Metadata: &trustmanagerapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data: []byte("data"),
					target: &trustmanagerapi.KeyValueTarget{
						Metadata: &trustmanagerapi.TargetMetadata{
							Labels: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data: []byte("data"),
					target: &trustmanagerapi.KeyValueTarget{
						Metadata: &trustmanagerapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value2"},
							Labels:      map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data: []byte("data"),
					target: &trustmanagerapi.KeyValueTarget{
						Metadata: &trustmanagerapi.TargetMetadata{
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

			inputHash := TrustBundleHash(test.input.data, test.input.target)
			for _, match := range test.matches {
				matchHash := TrustBundleHash(match.data, match.target)
				assert.Equal(t, inputHash, matchHash)
			}

			for _, mismatch := range test.mismatches {
				mismatchHash := TrustBundleHash(mismatch.data, mismatch.target)
				assert.NotEqual(t, inputHash, mismatchHash)
			}
		})
	}
}

func assertJKSData(t *testing.T, binData []byte, password string) {
	t.Helper()

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

func assertPKCS12Data(t *testing.T, binData []byte, password string) {
	t.Helper()

	cas, err := pkcs12.DecodeTrustStore(binData, password)
	assert.NoError(t, err)
	assert.Len(t, cas, 1)

	// Only one certificate block for this test, so we can safely ignore the `remaining` byte array
	p, _ := pem.Decode([]byte(data))
	assert.Equal(t, p.Bytes, cas[0].Raw)
}
