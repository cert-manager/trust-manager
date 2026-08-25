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

	"github.com/go-logr/logr"
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

	// The default PKCS12 password is empty, which produces a password-less truststore where the
	// profile has no effect. The profile test cases need a real password.
	customPKCS12Password = "pkcs12-password"
)

func Test_ApplyTarget_ConfigMap(t *testing.T) {
	bundleHash := TrustBundleHash([]byte(data), nil, nil)

	tests := map[string]struct {
		object runtime.Object
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Password of the PKCS12 truststore, empty means the default password
		pkcs12Password string
		// Encryption profile of the PKCS12 truststore
		pkcs12Profile trustapi.PKCS12Profile
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
		"if object exists with owner but outdated PKCS12 profile, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: pkcs12ProfileHash(trustapi.LegacyRC2PKCS12Profile)},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, []string{pkcs12Key}),
				},
				Data:       map[string]string{key: data},
				BinaryData: map[string][]byte{pkcs12Key: []byte("legacy profile truststore")},
			},
			withPKCS12:     true,
			pkcs12Password: customPKCS12Password,
			pkcs12Profile:  trustapi.Modern2023PKCS12Profile,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with owner and unchanged PKCS12 profile, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: pkcs12ProfileHash(trustapi.Modern2023PKCS12Profile)},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key}, []string{pkcs12Key}),
				},
				Data:       map[string]string{key: data},
				BinaryData: map[string][]byte{pkcs12Key: []byte("modern profile truststore")},
			},
			withPKCS12:     true,
			pkcs12Password: customPKCS12Password,
			pkcs12Profile:  trustapi.Modern2023PKCS12Profile,
			expNeedsUpdate: false,
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               "another-bundle",
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					ConfigMap:         &trustapi.TargetTemplate{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			resolvedBundle := source.BundleData{CertPool: certPool}
			if tt.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
					Password: trustapi.DefaultJKSPassword,
				}
			}
			pkcs12Password := trustapi.DefaultPKCS12Password
			if tt.pkcs12Password != "" {
				pkcs12Password = tt.pkcs12Password
			}
			if tt.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
					Password: new(pkcs12Password),
					Profile:  tt.pkcs12Profile,
				}
			}
			if tt.withTargetAnnotation {
				spec.Target.ConfigMap.Metadata.Annotations = map[string]string{targetAnnotation: "true"}
			}
			if tt.withTargetLabel {
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

			assert.Equalf(t, tt.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", tt.expNeedsUpdate, needsUpdate)

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
				assert.Equal(t, tt.expJKS, jksExists)

				if tt.expJKS {
					assertJKSData(t, binData, trustapi.DefaultJKSPassword)
				}

				binData, pkcs12Exists := configmap.BinaryData[pkcs12Key]
				assert.Equal(t, tt.expPKCS12, pkcs12Exists)

				if tt.expPKCS12 {
					assertPKCS12Data(t, binData, pkcs12Password)
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
	bundleHash := TrustBundleHash([]byte(data), nil, nil)

	tests := map[string]struct {
		object runtime.Object
		// Add JKS to AdditionalFormats
		withJKS bool
		// Add PKCS12 to AdditionalFormats
		withPKCS12 bool
		// Password of the PKCS12 truststore, empty means the default password
		pkcs12Password string
		// Encryption profile of the PKCS12 truststore
		pkcs12Profile trustapi.PKCS12Profile
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
		"if object exists with owner but outdated PKCS12 profile, expect update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: pkcs12ProfileHash(trustapi.LegacyRC2PKCS12Profile)},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key, pkcs12Key}, nil),
				},
				Data: map[string][]byte{
					key:       []byte(data),
					pkcs12Key: []byte("legacy profile truststore"),
				},
			},
			withPKCS12:     true,
			pkcs12Password: customPKCS12Password,
			pkcs12Profile:  trustapi.Modern2023PKCS12Profile,
			expPKCS12:      true,
			expNeedsUpdate: true,
		},
		"if object exists with owner and unchanged PKCS12 profile, expect no update": {
			object: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:        bundleName,
					Namespace:   namespace,
					Labels:      map[string]string{trustapi.BundleLabelKey: bundleName},
					Annotations: map[string]string{trustapi.BundleHashAnnotationKey: pkcs12ProfileHash(trustapi.Modern2023PKCS12Profile)},
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
					},
					ManagedFields: ssa_client.ManagedFieldEntries([]string{key, pkcs12Key}, nil),
				},
				Data: map[string][]byte{
					key:       []byte(data),
					pkcs12Key: []byte("modern profile truststore"),
				},
			},
			withPKCS12:     true,
			pkcs12Password: customPKCS12Password,
			pkcs12Profile:  trustapi.Modern2023PKCS12Profile,
			expNeedsUpdate: false,
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
						},
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               "another-bundle",
							Controller:         new(true),
							BlockOwnerDeletion: new(true),
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

			spec := trustapi.BundleSpec{
				Target: trustapi.BundleTarget{
					Secret:            &trustapi.TargetTemplate{Key: key},
					AdditionalFormats: &trustapi.AdditionalFormats{},
				},
			}
			resolvedBundle := source.BundleData{CertPool: certPool}
			if tt.withJKS {
				spec.Target.AdditionalFormats.JKS = &trustapi.JKS{
					KeySelector: trustapi.KeySelector{
						Key: jksKey,
					},
					Password: trustapi.DefaultJKSPassword,
				}
			}
			pkcs12Password := trustapi.DefaultPKCS12Password
			if tt.pkcs12Password != "" {
				pkcs12Password = tt.pkcs12Password
			}
			if tt.withPKCS12 {
				spec.Target.AdditionalFormats.PKCS12 = &trustapi.PKCS12{
					KeySelector: trustapi.KeySelector{
						Key: pkcs12Key,
					},
					Password: new(pkcs12Password),
					Profile:  tt.pkcs12Profile,
				}
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

			assert.Equalf(t, tt.expNeedsUpdate, needsUpdate, "unexpected needsUpdate, exp=%t got=%t", tt.expNeedsUpdate, needsUpdate)

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
				assert.Equal(t, tt.expJKS, jksExists)

				if tt.expJKS {
					assertJKSData(t, binData, trustapi.DefaultJKSPassword)
				}

				binData, pkcs12Exists := secret.Data[pkcs12Key]
				assert.Equal(t, tt.expPKCS12, pkcs12Exists)

				if tt.expPKCS12 {
					assertPKCS12Data(t, binData, pkcs12Password)
				}
			}
		})
	}
}

// Test_ApplyTarget_LogsAppliedKeys ensures that the reconciler logs exactly which keys
// were applied to the target, and to which field. Additional formats are binary and are
// written to the binaryData field of target ConfigMaps, which is not displayed by some
// Kubernetes UIs. The log allows verifying from the logs alone that additional formats
// were synced (see issue #800).
func Test_ApplyTarget_LogsAppliedKeys(t *testing.T) {
	additionalFormats := &trustapi.AdditionalFormats{
		JKS: &trustapi.JKS{
			KeySelector: trustapi.KeySelector{Key: jksKey},
			Password:    trustapi.DefaultJKSPassword,
		},
		PKCS12: &trustapi.PKCS12{
			KeySelector: trustapi.KeySelector{Key: pkcs12Key},
			Password:    ptr.To(trustapi.DefaultPKCS12Password),
		},
	}

	tests := map[string]struct {
		kind       Kind
		target     trustapi.BundleTarget
		expLogArgs []any
	}{
		"ConfigMap target should log data and binaryData keys": {
			kind: KindConfigMap,
			target: trustapi.BundleTarget{
				ConfigMap:         &trustapi.TargetTemplate{Key: key},
				AdditionalFormats: additionalFormats,
			},
			expLogArgs: []any{
				"dataKeys", []string{key},
				"binaryDataKeys", []string{jksKey, pkcs12Key},
			},
		},
		"Secret target should log data keys": {
			kind: KindSecret,
			target: trustapi.BundleTarget{
				Secret:            &trustapi.TargetTemplate{Key: key},
				AdditionalFormats: additionalFormats,
			},
			expLogArgs: []any{
				"dataKeys", []string{jksKey, pkcs12Key, key},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fakeClient := fake.NewClientBuilder().
				WithReturnManagedFields().
				WithScheme(test.Scheme).
				Build()

			r := &Reconciler{
				Client: fakeClient,
				Cache:  fakeClient,
				PatchResourceOverwrite: func(_ context.Context, _ any) error {
					return nil
				},
			}

			certPool := util.NewCertPool()
			err := certPool.AddCertsFromPEM([]byte(data))
			assert.NoError(t, err)

			logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.BufferLogs(true)))
			ctx := logr.NewContext(t.Context(), logger)
			synced, err := r.ApplyTarget(ctx, Resource{
				Kind:           tt.kind,
				NamespacedName: types.NamespacedName{Name: bundleName, Namespace: namespace},
			}, &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       trustapi.BundleSpec{Target: tt.target},
			}, source.BundleData{CertPool: certPool})
			assert.NoError(t, err)
			assert.True(t, synced)

			underlier, ok := logger.GetSink().(ktesting.Underlier)
			if !ok {
				t.Fatalf("expected logger sink to implement ktesting.Underlier, got %T", logger.GetSink())
			}

			found := false
			for _, entry := range underlier.GetBuffer().Data() {
				if entry.Message != "applied bundle to namespace" {
					continue
				}
				found = true
				assert.Equal(t, tt.expLogArgs, entry.ParameterKVList)
			}
			assert.True(t, found, "expected %q to be logged", "applied bundle to namespace")
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
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: ""}}},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{}}},
				// NOTE: default passwords are applied by openapi, so the input arguments for the function
				// will never have a password of "". And we don't have to account for it in the test.
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("")}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: nil},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: "nonempty"}}},
				{data: []byte{}, additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("nonempty")}}},
			},
		},
		"non-empty data": {
			input: inputArgs{data: []byte("data"), additionalFormats: nil},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: nil},
			},
		},
		"jks password": {
			input: inputArgs{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: "password"}}},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: "password"}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.JKS{Password: "wrong"}}},
			},
		},
		"pkcs12 password": {
			input: inputArgs{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password")}}},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password")}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("wrong")}}},
			},
		},
		"pkcs12 profile": {
			input: inputArgs{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password"), Profile: trustapi.LegacyRC2PKCS12Profile}}},
			matches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password"), Profile: trustapi.LegacyRC2PKCS12Profile}}},
			},
			mismatches: []inputArgs{
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password"), Profile: trustapi.LegacyDESPKCS12Profile}}},
				{data: []byte("data"), additionalFormats: &trustapi.AdditionalFormats{PKCS12: &trustapi.PKCS12{Password: new("password"), Profile: trustapi.Modern2023PKCS12Profile}}},
			},
		},
		"target metadata": {
			input: inputArgs{
				data:              []byte("data"),
				additionalFormats: &trustapi.AdditionalFormats{},
				targetTemplate: &trustapi.TargetTemplate{
					Metadata: trustapi.TargetMetadata{
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
						Metadata: trustapi.TargetMetadata{
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
						Metadata: trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: trustapi.TargetMetadata{
							Labels: map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: trustapi.TargetMetadata{
							Annotations: map[string]string{"annotation1": "value2"},
							Labels:      map[string]string{"annotation1": "value1"},
						},
					},
				},
				{
					data:              []byte("data"),
					additionalFormats: &trustapi.AdditionalFormats{},
					targetTemplate: &trustapi.TargetTemplate{
						Metadata: trustapi.TargetMetadata{
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

// pkcs12ProfileHash returns the hash a target would carry after being synced with the given
// PKCS12 profile, so a test case can start from a target synced with an older profile.
func pkcs12ProfileHash(profile trustapi.PKCS12Profile) string {
	return TrustBundleHash([]byte(data), &trustapi.AdditionalFormats{
		PKCS12: &trustapi.PKCS12{
			KeySelector: trustapi.KeySelector{Key: pkcs12Key},
			Password:    new(customPKCS12Password),
			Profile:     profile,
		},
	}, nil)
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

func Test_TrustBundleHash_Deterministic(t *testing.T) {
	// Regression test for #971: TrustBundleHash folded the target annotations and
	// labels into the hash by iterating Go maps directly. With more than one key,
	// Go's randomized map iteration order made the hash vary between calls, so
	// needsUpdate() was always true and the controller rewrote the target on every
	// reconcile. The hash must be stable across calls for the same input.
	//
	// Note: this needs multiple keys to expose the bug — a single annotation/label
	// (as in the existing integration tests) cannot trigger the randomization.
	target := &trustapi.TargetTemplate{
		Metadata: trustapi.TargetMetadata{
			Annotations: map[string]string{
				"annotation1": "value1",
				"annotation2": "value2",
				"annotation3": "value3",
				"annotation4": "value4",
				"annotation5": "value5",
			},
			Labels: map[string]string{
				"label1": "value1",
				"label2": "value2",
				"label3": "value3",
				"label4": "value4",
				"label5": "value5",
			},
		},
	}

	want := TrustBundleHash([]byte("data"), nil, target)
	for i := range 1000 {
		if got := TrustBundleHash([]byte("data"), nil, target); got != want {
			t.Fatalf("TrustBundleHash must be deterministic, but iteration %d produced %q, want %q", i, got, want)
		}
	}
}
