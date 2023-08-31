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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2/klogr"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test/dummy"
	"github.com/cert-manager/trust-manager/test/gen"
)

func Test_Reconcile(t *testing.T) {
	const (
		trustNamespace = "trust-namespace"

		sourceConfigMapName = "source-configmap"
		sourceConfigMapKey  = "configmap-key"
		sourceSecretName    = "source-secret"
		sourceSecretKey     = "secret-key"

		targetKey = "target-key"

		bundleName             = "test-bundle"
		bundleGeneration int64 = 2
	)

	var (
		sourceConfigMap client.Object = &corev1.ConfigMap{
			TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      sourceConfigMapName,
				Namespace: trustNamespace,
			},
			Data: map[string]string{
				"configmap-key": dummy.TestCertificate1,
			},
		}
		sourceSecret client.Object = &corev1.Secret{
			TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:      sourceSecretName,
				Namespace: trustNamespace,
			},
			Data: map[string][]byte{
				"secret-key": []byte(dummy.TestCertificate2),
			},
		}

		baseBundle = &trustapi.Bundle{
			TypeMeta: metav1.TypeMeta{Kind: "Bundle", APIVersion: "trust.cert-manager.io/v1alpha1"},
			ObjectMeta: metav1.ObjectMeta{
				Name:            bundleName,
				Generation:      bundleGeneration,
				UID:             "123",
				ResourceVersion: "1000",
			},
			Spec: trustapi.BundleSpec{
				Sources: []trustapi.BundleSource{
					{ConfigMap: &trustapi.SourceObjectKeySelector{Name: sourceConfigMapName, KeySelector: trustapi.KeySelector{Key: sourceConfigMapKey}}},
					{Secret: &trustapi.SourceObjectKeySelector{Name: sourceSecretName, KeySelector: trustapi.KeySelector{Key: sourceSecretKey}}},
					{InLine: ptr.To(dummy.TestCertificate3)},
				},
				Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
			},
		}

		baseBundleOwnerRef = []metav1.OwnerReference{*metav1.NewControllerRef(baseBundle, trustapi.SchemeGroupVersion.WithKind("Bundle"))}

		namespaces = []client.Object{
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: trustNamespace}},
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-1"}},
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-2"}},
		}

		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)

		testDefaultPackage = &fspkg.Package{
			Name:    "testpkg",
			Version: "123",
			Bundle:  dummy.TestCertificate5,
		}
	)

	tests := map[string]struct {
		existingSecrets         []client.Object
		existingConfigMaps      []client.Object
		existingNamespaces      []client.Object
		existingBundles         []client.Object
		configureDefaultPackage bool
		expResult               ctrl.Result
		expError                bool
		expObjects              []client.Object
		expEvent                string
	}{
		"if no bundle exists, should return nothing": {
			existingSecrets:    []client.Object{sourceSecret},
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingNamespaces: namespaces,
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects:         append(namespaces, sourceConfigMap, sourceSecret),
			expEvent:           "",
		},
		"if Bundle references a ConfigMap which does not exist, update with 'not found'": {
			existingSecrets:    []client.Object{sourceSecret},
			existingNamespaces: namespaces,
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionFalse,
							Reason:             "SourceNotFound",
							Message:            `Bundle source was not found: failed to retrieve bundle from source: configmaps "source-configmap" not found`,
							ObservedGeneration: bundleGeneration,
							LastTransitionTime: fixedmetatime,
						},
					}}),
				),
			),
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to retrieve bundle from source: configmaps "source-configmap" not found`,
		},
		"if Bundle references a ConfigMap whose key doesn't exist, update with 'not found'": {
			existingSecrets:    []client.Object{sourceSecret},
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceConfigMapName}}},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceSecret,
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceConfigMapName, ResourceVersion: "999"},
				},
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionFalse,
							Reason:             "SourceNotFound",
							Message:            `Bundle source was not found: failed to retrieve bundle from source: no data found in ConfigMap trust-namespace/source-configmap at key "configmap-key"`,
							ObservedGeneration: bundleGeneration,
							LastTransitionTime: fixedmetatime,
						},
					}}),
				),
			),
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to retrieve bundle from source: no data found in ConfigMap trust-namespace/source-configmap at key "configmap-key"`,
		},
		"if Bundle references a Secret which does not exist, update with 'not found'": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceConfigMap,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionFalse,
							Reason:             "SourceNotFound",
							Message:            `Bundle source was not found: failed to retrieve bundle from source: secrets "source-secret" not found`,
							ObservedGeneration: bundleGeneration,
							LastTransitionTime: fixedmetatime,
						},
					}}),
				),
			),
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to retrieve bundle from source: secrets "source-secret" not found`,
		},
		"if Bundle references a Secret whose key doesn't exist, update with 'not found'": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceSecretName}}},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceConfigMap,
				&corev1.Secret{
					TypeMeta:   metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceSecretName, ResourceVersion: "999"},
				},
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionFalse,
							Reason:             "SourceNotFound",
							Message:            `Bundle source was not found: failed to retrieve bundle from source: no data found in Secret trust-namespace/source-secret at key "secret-key"`,
							ObservedGeneration: bundleGeneration,
							LastTransitionTime: fixedmetatime,
						},
					}}),
				),
			),
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to retrieve bundle from source: no data found in Secret trust-namespace/source-secret at key "secret-key"`,
		},
		"if Bundle Status Target doesn't match the Spec Target, delete old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap, &corev1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name}, Data: map[string]string{"A": "B", "old-target": "foo"},
			},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name}, Data: map[string]string{"A": "B", "old-target": "foo"},
				}},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "old-target"}}}),
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			expResult:       ctrl.Result{},
			expError:        false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}}}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
			),
			expEvent: "Normal DeleteOldTarget Deleting old targets as Bundle target has been modified",
		},
		"if Bundle Status Target doesn't match the Spec Target, delete all old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name}, Data: map[string]string{"A": "B", "old-target": "foo"}, BinaryData: map[string][]byte{"target.jks": []byte("foo")},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name}, Data: map[string]string{"A": "B", "old-target": "foo"}, BinaryData: map[string][]byte{"target.jks": []byte("foo")},
				}},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}}),
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{
						ConfigMap:         &trustapi.KeySelector{Key: "old-target"},
						AdditionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}},
					}}),
				)},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleTargetAdditionalFormats(trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}}),
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{
						ConfigMap:         &trustapi.KeySelector{Key: targetKey},
						AdditionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}},
					}}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
			),
			expEvent: "Normal DeleteOldTarget Deleting old targets as Bundle target has been modified",
		},
		"if Bundle Status Target.AdditionalFormats.JKS doesn't match the Spec Target.AdditionalFormats.JKS, delete old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name}, Data: map[string]string{"A": "B", targetKey: "foo"}, BinaryData: map[string][]byte{"old-target.jks": []byte("foo")},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name}, Data: map[string]string{"A": "B", targetKey: "foo"}, BinaryData: map[string][]byte{"old-target.jks": []byte("foo")},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}}),
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{
						ConfigMap:         &trustapi.KeySelector{Key: targetKey},
						AdditionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "old-target.jks"}},
					}}),
				),
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleTargetAdditionalFormats(trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}}),
					gen.SetBundleStatus(trustapi.BundleStatus{Target: &trustapi.BundleTarget{
						ConfigMap:         &trustapi.KeySelector{Key: targetKey},
						AdditionalFormats: &trustapi.AdditionalFormats{JKS: &trustapi.KeySelector{Key: "target.jks"}},
					}}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, ResourceVersion: "1000"}, Data: map[string]string{"A": "B"},
				},
			),
			expEvent: "Normal DeleteOldTarget Deleting old targets as Bundle target has been modified",
		},
		"if Bundle not synced everywhere, sync and update Synced": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle not synced everywhere, sync except Namespaces that are terminating and update Synced": {
			existingNamespaces: append(namespaces,
				&corev1.Namespace{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "random-namespace"},
					Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
				},
			),
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionTrue,
							LastTransitionTime: fixedmetatime,
							Reason:             "Synced",
							Message:            "Successfully synced Bundle to all namespaces",
							ObservedGeneration: bundleGeneration,
						}},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle not synced everywhere, sync except Namespaces that don't match labels and update Synced": {
			existingNamespaces: append(namespaces,
				&corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "random-namespace",
						Labels: map[string]string{"foo": "bar"},
					},
				},
				&corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "another-random-namespace",
						Labels: map[string]string{"foo": "bar"},
					},
				},
			),
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				gen.SetBundleTargetNamespaceSelectorMatchLabels(map[string]string{"foo": "bar"}))},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleTargetNamespaceSelectorMatchLabels(map[string]string{"foo": "bar"}),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{
							ConfigMap: &trustapi.KeySelector{Key: targetKey},
							NamespaceSelector: &trustapi.NamespaceSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
						Conditions: []trustapi.BundleCondition{{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionTrue,
							LastTransitionTime: &metav1.Time{Time: fixedclock.Now().Local()},
							Reason:             "Synced",
							Message:            "Successfully synced Bundle to namespaces that match this label selector: foo=bar",
							ObservedGeneration: bundleGeneration,
						}},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "random-namespace", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "another-random-namespace", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "Normal Synced Successfully synced Bundle to namespaces that match this label selector: foo=bar",
		},
		"if Bundle not synced everywhere, sync except Namespaces that don't match labels and update Synced. Should delete ConfigMaps in wrong namespaces.": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				gen.SetBundleTargetNamespaceSelectorMatchLabels(map[string]string{"foo": "bar"}))},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleTargetNamespaceSelectorMatchLabels(map[string]string{"foo": "bar"}),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{
							ConfigMap: &trustapi.KeySelector{Key: targetKey},
							NamespaceSelector: &trustapi.NamespaceSelector{
								MatchLabels: map[string]string{"foo": "bar"},
							},
						},
						Conditions: []trustapi.BundleCondition{{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionTrue,
							LastTransitionTime: &metav1.Time{Time: fixedclock.Now().Local()},
							Reason:             "Synced",
							Message:            "Successfully synced Bundle to namespaces that match this label selector: foo=bar",
							ObservedGeneration: bundleGeneration,
						}},
					}),
				),
			),
			expEvent: "Normal Synced Successfully synced Bundle to namespaces that match this label selector: foo=bar",
		},
		"if Bundle synced but doesn't have owner reference, should sync and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{
							ConfigMap: &trustapi.KeySelector{Key: targetKey},
						},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration - 1,
							},
						},
					})),
			},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle synced but doesn't have condition, should add condition": {
			existingNamespaces: namespaces,
			existingSecrets:    []client.Object{sourceSecret},
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle)},
			expResult:       ctrl.Result{},
			expError:        false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle synced, should do nothing": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
			},

			expResult: ctrl.Result{},
			expError:  false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1000"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "999"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: "",
		},
		"if Bundle references default CAs but it wasn't configured at startup, update with error": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle, gen.AppendBundleUsesDefaultPackage())},
			expResult:          ctrl.Result{},
			expError:           false,
			expObjects: append(namespaces, sourceConfigMap,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionFalse,
							Reason:             "SourceNotFound",
							Message:            `Bundle source was not found: failed to retrieve bundle from source: no default package was specified when trust-manager was started; default CAs not available`,
							ObservedGeneration: bundleGeneration,
							LastTransitionTime: fixedmetatime,
						},
					}}),
					gen.AppendBundleUsesDefaultPackage(),
				),
			),
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to retrieve bundle from source: no default package was specified when trust-manager was started; default CAs not available`,
		},
		"if Bundle references the configured default CAs, update targets with the CAs and ensure Bundle status references the configured default package version": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.AppendBundleUsesDefaultPackage(),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
					}),
				),
			},
			configureDefaultPackage: true,
			expResult:               ctrl.Result{},
			expError:                false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.AppendBundleUsesDefaultPackage(),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
						DefaultCAPackageVersion: ptr.To(testDefaultPackage.StringID()),
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
			),
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
		"if Bundle removes reference to default package, remove version from Bundle Status and update targets": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef},
					Data:       map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5)},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				gen.SetBundleStatus(trustapi.BundleStatus{
					Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
					Conditions: []trustapi.BundleCondition{
						{
							Type:               trustapi.BundleConditionSynced,
							Status:             metav1.ConditionTrue,
							LastTransitionTime: fixedmetatime,
							Reason:             "Synced",
							Message:            "Successfully synced Bundle to all namespaces",
							ObservedGeneration: bundleGeneration,
						},
					},
					DefaultCAPackageVersion: ptr.To(testDefaultPackage.StringID()),
				}),
			)},
			configureDefaultPackage: true,
			expResult:               ctrl.Result{},
			expError:                false,
			expObjects: append(namespaces, sourceConfigMap, sourceSecret,
				gen.BundleFrom(baseBundle,
					gen.SetBundleResourceVersion("1001"),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Target: &trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: targetKey}},
						Conditions: []trustapi.BundleCondition{
							{
								Type:               trustapi.BundleConditionSynced,
								Status:             metav1.ConditionTrue,
								LastTransitionTime: fixedmetatime,
								Reason:             "Synced",
								Message:            "Successfully synced Bundle to all namespaces",
								ObservedGeneration: bundleGeneration,
							},
						},
						DefaultCAPackageVersion: nil,
					}),
				),
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-1", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
				&corev1.ConfigMap{
					TypeMeta:   metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns-2", Name: baseBundle.Name, OwnerReferences: baseBundleOwnerRef, ResourceVersion: "1000"},
					Data:       map[string]string{targetKey: dummy.DefaultJoinedCerts()},
				},
			),
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(trustapi.GlobalScheme).
				WithObjects(test.existingConfigMaps...).
				WithObjects(test.existingBundles...).
				WithObjects(test.existingNamespaces...).
				WithObjects(test.existingSecrets...).
				WithStatusSubresource(test.existingNamespaces...).
				WithStatusSubresource(test.existingBundles...).
				Build()

			fakerecorder := record.NewFakeRecorder(1)

			b := &bundle{
				client:   fakeclient,
				recorder: fakerecorder,
				clock:    fixedclock,
				Options: Options{
					Log:       klogr.New(),
					Namespace: trustNamespace,
				},
			}

			if test.configureDefaultPackage {
				b.defaultPackage = testDefaultPackage.Clone()
			}

			resp, err := b.Reconcile(context.TODO(), ctrl.Request{NamespacedName: types.NamespacedName{Name: bundleName}})
			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}

			if !apiequality.Semantic.DeepEqual(resp, test.expResult) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expResult, resp)
			}

			var event string
			select {
			case event = <-fakerecorder.Events:
			default:
			}
			assert.Equal(t, test.expEvent, event)

			for _, expObj := range test.expObjects {
				var actual client.Object
				switch expObj.(type) {
				case *corev1.Secret:
					actual = &corev1.Secret{}
				case *corev1.ConfigMap:
					actual = &corev1.ConfigMap{}
				case *corev1.Namespace:
					actual = &corev1.Namespace{}
				case *trustapi.Bundle:
					actual = &trustapi.Bundle{}
				default:
					t.Errorf("unexpected object kind in expected: %#+v", expObj)
				}

				err := fakeclient.Get(context.TODO(), client.ObjectKeyFromObject(expObj), actual)
				assert.NoError(t, err)
				if !apiequality.Semantic.DeepEqual(expObj, actual) {
					t.Errorf("unexpected expected object\nexp=%#+v\ngot=%#+v", expObj, actual)
				}
			}
		})
	}
}
