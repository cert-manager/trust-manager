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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	coreapplyconfig "k8s.io/client-go/applyconfigurations/core/v1"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/klog/v2/ktesting"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/ssa_client"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/target"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/truststore"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test"
	"github.com/cert-manager/trust-manager/test/dummy"
	"github.com/cert-manager/trust-manager/test/gen"
)

func testEncodePKCS12(t *testing.T, data string) []byte {
	t.Helper()

	certPool := util.NewCertPool()
	if err := certPool.AddCertsFromPEM([]byte(data)); err != nil {
		t.Fatal(err)
	}

	encoded, err := truststore.NewPKCS12Encoder(trustapi.DefaultPKCS12Password, trustapi.Modern2023PKCS12Profile).Encode(certPool)
	if err != nil {
		t.Error(err)
	}

	return encoded
}

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
					{ConfigMap: &trustapi.SourceObjectKeySelector{Name: sourceConfigMapName, Key: sourceConfigMapKey}},
					{Secret: &trustapi.SourceObjectKeySelector{Name: sourceSecretName, Key: sourceSecretKey}},
					{InLine: ptr.To(dummy.TestCertificate3)},
				},
				Target: &trustapi.BundleTarget{ConfigMap: trustapi.TargetTemplate{Key: targetKey}},
			},
		}

		baseBundleLabels = map[string]string{trustapi.BundleLabelKey: bundleName}

		baseBundleOwnerRef = []metav1.OwnerReference{*metav1.NewControllerRef(baseBundle, trustapi.SchemeGroupVersion.WithKind(trustapi.BundleKind))}

		namespaces = []client.Object{
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: trustNamespace}},
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-1"}},
			&corev1.Namespace{TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "ns-2"}},
		}

		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.Local) // nolint: gosmopolitan // metav1.Time when unmarshalled returns a local time
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)

		testDefaultPackage = &fspkg.Package{
			Name:    "testpkg",
			Version: "123",
			Bundle:  dummy.TestCertificate5,
		}

		pkcs12DefaultAdditionalFormats = trustapi.AdditionalFormats{
			PKCS12: trustapi.PKCS12{
				KeySelector: trustapi.KeySelector{
					Key: "target.p12",
				},
				Password: ptr.To(trustapi.DefaultPKCS12Password),
			},
		}
		pkcs12DefaultAdditionalFormatsOldPassword = trustapi.AdditionalFormats{
			PKCS12: trustapi.PKCS12{
				KeySelector: trustapi.KeySelector{
					Key: "target.p12",
				},
				Password: ptr.To("OLD PASSWORD"),
			},
		}

		configMapPatch = func(name, namespace string, data map[string]string, binData map[string][]byte, key *string, additionalFormats *trustapi.AdditionalFormats) *coreapplyconfig.ConfigMapApplyConfiguration {
			annotations := map[string]string{}
			if key != nil {
				annotations[trustapi.BundleHashAnnotationKey] = target.TrustBundleHash([]byte(data[*key]), additionalFormats, nil)
			}

			return coreapplyconfig.
				ConfigMap(name, namespace).
				WithLabels(map[string]string{
					trustapi.BundleLabelKey: baseBundle.GetName(),
				}).
				WithAnnotations(annotations).
				WithOwnerReferences(
					v1.OwnerReference().
						WithAPIVersion(trustapi.SchemeGroupVersion.String()).
						WithKind(trustapi.BundleKind).
						WithName(baseBundle.GetName()).
						WithUID(baseBundle.GetUID()).
						WithBlockOwnerDeletion(true).
						WithController(true),
				).
				WithData(data).
				WithBinaryData(binData)
		}

		secretPatch = func(name, namespace string, data map[string]string, key *string, additionaFormats *trustapi.AdditionalFormats) *coreapplyconfig.SecretApplyConfiguration {
			annotations := map[string]string{}
			if key != nil {
				annotations[trustapi.BundleHashAnnotationKey] = target.TrustBundleHash([]byte(data[*key]), additionaFormats, nil)
			}

			binaryData := map[string][]byte{}
			for k, v := range data {
				binaryData[k] = []byte(v)
			}

			return coreapplyconfig.
				Secret(name, namespace).
				WithLabels(map[string]string{
					trustapi.BundleLabelKey: baseBundle.GetName(),
				}).
				WithAnnotations(annotations).
				WithOwnerReferences(
					v1.OwnerReference().
						WithAPIVersion(trustapi.SchemeGroupVersion.String()).
						WithKind(trustapi.BundleKind).
						WithName(baseBundle.GetName()).
						WithUID(baseBundle.GetUID()).
						WithBlockOwnerDeletion(true).
						WithController(true),
				).
				WithData(binaryData)
		}

		targetConfigMap = func(namespace string, data map[string]string, binData map[string][]byte, key *string, withOwnerRef bool, additionaFormats *trustapi.AdditionalFormats) *corev1.ConfigMap {
			annotations := map[string]string{}
			if key != nil {
				annotations[trustapi.BundleHashAnnotationKey] = target.TrustBundleHash([]byte(data[*key]), additionaFormats, nil)
			}

			dataEntries := make([]string, 0, len(data))
			for k := range data {
				dataEntries = append(dataEntries, k)
			}

			binDataEntries := make([]string, 0, len(binData))
			for k := range binData {
				binDataEntries = append(binDataEntries, k)
			}

			configmap := &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       namespace,
					Name:            baseBundle.Name,
					Labels:          baseBundleLabels,
					Annotations:     annotations,
					OwnerReferences: baseBundleOwnerRef,
					ManagedFields:   ssa_client.ManagedFieldEntries(dataEntries, binDataEntries),
				},
				Data:       data,
				BinaryData: binData,
			}

			if !withOwnerRef {
				configmap.OwnerReferences = nil
			}

			return configmap
		}

		targetSecret = func(namespace string, data map[string]string, key *string, withOwnerRef bool, additionaFormats *trustapi.AdditionalFormats) *corev1.Secret {
			annotations := map[string]string{}
			if key != nil {
				annotations[trustapi.BundleHashAnnotationKey] = target.TrustBundleHash([]byte(data[*key]), additionaFormats, nil)
			}

			dataEntries := make([]string, 0, len(data))
			for k := range data {
				dataEntries = append(dataEntries, k)
			}

			binaryData := map[string][]byte{}
			for k, v := range data {
				binaryData[k] = []byte(v)
			}

			secret := &corev1.Secret{
				TypeMeta: metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:       namespace,
					Name:            baseBundle.Name,
					Labels:          baseBundleLabels,
					Annotations:     annotations,
					OwnerReferences: baseBundleOwnerRef,
					ManagedFields:   ssa_client.ManagedFieldEntries(dataEntries, nil),
				},
				Data: binaryData,
			}

			if !withOwnerRef {
				secret.OwnerReferences = nil
			}

			return secret
		}
	)

	tests := map[string]struct {
		existingSecrets         []client.Object
		existingConfigMaps      []client.Object
		existingNamespaces      []client.Object
		existingBundles         []client.Object
		configureDefaultPackage bool
		disableSecretTargets    bool
		expResult               ctrl.Result
		expError                bool
		expPatches              []any
		expBundlePatch          *trustapi.BundleStatus
		expEvent                string
		targetNamespaces        []string
	}{
		"if no bundle exists, should return nothing": {
			existingSecrets:    []client.Object{sourceSecret},
			existingConfigMaps: []client.Object{sourceConfigMap},
			expError:           false,
			expEvent:           "",
		},
		"if Bundle references a ConfigMap which does not exist, update with 'not found'": {
			existingSecrets:    []client.Object{sourceSecret},
			existingNamespaces: namespaces,
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expError:           false,
			expBundlePatch: &trustapi.BundleStatus{Conditions: []metav1.Condition{
				{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SourceNotFound",
					Message:            `Bundle source was not found: failed to get ConfigMap trust-namespace/source-configmap: configmaps "source-configmap" not found`,
					ObservedGeneration: bundleGeneration,
					LastTransitionTime: fixedmetatime,
				},
			}},
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to get ConfigMap trust-namespace/source-configmap: configmaps "source-configmap" not found`,
		},
		"if Bundle references a ConfigMap whose key doesn't exist, update with 'not found'": {
			existingSecrets:    []client.Object{sourceSecret},
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceConfigMapName}}},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expError:           false,
			expBundlePatch: &trustapi.BundleStatus{Conditions: []metav1.Condition{
				{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SourceNotFound",
					Message:            `Bundle source was not found: no data found in ConfigMap trust-namespace/source-configmap at key "configmap-key"`,
					ObservedGeneration: bundleGeneration,
					LastTransitionTime: fixedmetatime,
				},
			}},
			expEvent: `Warning SourceNotFound Bundle source was not found: no data found in ConfigMap trust-namespace/source-configmap at key "configmap-key"`,
		},
		"if Bundle references a Secret which does not exist, update with 'not found'": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expError:           false,
			expBundlePatch: &trustapi.BundleStatus{Conditions: []metav1.Condition{
				{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SourceNotFound",
					Message:            `Bundle source was not found: failed to get Secret trust-namespace/source-secret: secrets "source-secret" not found`,
					ObservedGeneration: bundleGeneration,
					LastTransitionTime: fixedmetatime,
				},
			}},
			expEvent: `Warning SourceNotFound Bundle source was not found: failed to get Secret trust-namespace/source-secret: secrets "source-secret" not found`,
		},
		"if Bundle references a Secret whose key doesn't exist, update with 'not found'": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: trustNamespace, Name: sourceSecretName}}},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle)},
			expError:           false,
			expBundlePatch: &trustapi.BundleStatus{Conditions: []metav1.Condition{
				{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SourceNotFound",
					Message:            `Bundle source was not found: no data found in Secret trust-namespace/source-secret at key "secret-key"`,
					ObservedGeneration: bundleGeneration,
					LastTransitionTime: fixedmetatime,
				},
			}},
			expEvent: `Warning SourceNotFound Bundle source was not found: no data found in Secret trust-namespace/source-secret at key "secret-key"`,
		},
		"if Bundle configMap Target changes, delete old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					"ns-1",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					nil,
					ptr.To("old-target"),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					nil,
					ptr.To("old-target"),
					true, nil,
				),
			},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle),
			},
			existingSecrets: []client.Object{sourceSecret},
			expError:        false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle secret Target changes, delete old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets: []client.Object{sourceSecret,
				targetSecret(
					"ns-1",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					ptr.To("old-target"),
					true, nil,
				),
				targetSecret(
					"ns-2",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					ptr.To("old-target"),
					true, nil,
				),
			},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					func(b *trustapi.Bundle) {
						// swap target configmap for secret
						b.Spec.Target.ConfigMap, b.Spec.Target.Secret = b.Spec.Target.Secret, b.Spec.Target.ConfigMap
					},
				),
			},
			expError: false,
			expPatches: []any{
				secretPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle Status Target doesn't match the Spec Target, delete all old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					"ns-1",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					map[string][]byte{
						"target.p12": []byte("foo"),
					},
					ptr.To("old-target"),
					true, &pkcs12DefaultAdditionalFormats,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						"A":          "B",
						"old-target": "foo",
					},
					map[string][]byte{
						"target.p12": []byte("foo"),
					},
					ptr.To("old-target"),
					true, &pkcs12DefaultAdditionalFormats,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(pkcs12DefaultAdditionalFormats),
				)},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "trust-namespace", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle Status Target.AdditionalFormats.PKCS12 doesn't match the Spec Target.AdditionalFormats.PKCS12, delete old targets and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					"ns-1",
					map[string]string{
						"A":       "B",
						targetKey: "foo",
					},
					map[string][]byte{
						"old-target.p12": []byte("foo"),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						"A":       "B",
						targetKey: "foo",
					},
					map[string][]byte{
						"old-target.p12": []byte("foo"),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(pkcs12DefaultAdditionalFormats),
				),
			},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "trust-namespace", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if the PKCS12 password matches, don't patch": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(pkcs12DefaultAdditionalFormats),
				),
			},
			expError:   false,
			expPatches: []any{},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if the PKCS12 password changed, apply patch": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormatsOldPassword,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormatsOldPassword,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					map[string][]byte{
						"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
					},
					ptr.To(targetKey),
					true, &pkcs12DefaultAdditionalFormats,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleTargetAdditionalFormats(pkcs12DefaultAdditionalFormats),
				),
			},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "trust-namespace", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{
					targetKey: dummy.DefaultJoinedCerts(),
				}, map[string][]byte{
					"target.p12": testEncodePKCS12(t, dummy.DefaultJoinedCerts()),
				}, ptr.To(targetKey), &pkcs12DefaultAdditionalFormats),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle with secret and configmap target not synced everywhere, sync and update Synced": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				func(b *trustapi.Bundle) {
					// copy configmap target to secret target
					b.Spec.Target.Secret = b.Spec.Target.ConfigMap
				},
			)},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
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
			expError:           false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: fixedmetatime,
					Reason:             "Synced",
					Message:            "Successfully synced Bundle to all namespaces",
					ObservedGeneration: bundleGeneration,
				}},
			},
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
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "random-namespace", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "another-random-namespace", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: fixedmetatime,
					Reason:             "Synced",
					Message:            "Successfully synced Bundle to namespaces that match this label selector: foo=bar",
					ObservedGeneration: bundleGeneration,
				}},
			},
			expEvent: "Normal Synced Successfully synced Bundle to namespaces that match this label selector: foo=bar",
		},
		"if Bundle not synced everywhere, sync except Namespaces that don't match labels and update Synced. Should delete ConfigMaps in wrong namespaces.": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				gen.SetBundleTargetNamespaceSelectorMatchLabels(map[string]string{"foo": "bar"}),
			)},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{}, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{}, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{}, nil, nil, nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: fixedmetatime,
					Reason:             "Synced",
					Message:            "Successfully synced Bundle to namespaces that match this label selector: foo=bar",
					ObservedGeneration: bundleGeneration,
				}},
			},
			expEvent: "Normal Synced Successfully synced Bundle to namespaces that match this label selector: foo=bar",
		},
		"if Bundle synced but doesn't have owner reference, should sync and update": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					false, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					false, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					false, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleStatus(trustapi.BundleStatus{
						Conditions: []metav1.Condition{
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
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle synced but doesn't have condition, should add condition": {
			existingNamespaces: namespaces,
			existingSecrets:    []client.Object{sourceSecret},
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle)},
			expError:        false,
			expPatches:      nil,
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all namespaces",
		},
		"if Bundle synced, should do nothing": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.SetBundleStatus(trustapi.BundleStatus{
						Conditions: []metav1.Condition{
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

			expError:       false,
			expPatches:     nil,
			expBundlePatch: nil,
			expEvent:       "",
		},
		"if Bundle references default CAs but it wasn't configured at startup, update with error": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles:    []client.Object{gen.BundleFrom(baseBundle, gen.AppendBundleUsesDefaultPackage())},
			expError:           false,
			expPatches:         nil,
			expBundlePatch: &trustapi.BundleStatus{Conditions: []metav1.Condition{
				{
					Type:               trustapi.BundleConditionSynced,
					Status:             metav1.ConditionFalse,
					Reason:             "SourceNotFound",
					Message:            `Bundle source was not found: no default package was specified when trust-manager was started; default CAs not available`,
					ObservedGeneration: bundleGeneration,
					LastTransitionTime: fixedmetatime,
				},
			}},
			expEvent: `Warning SourceNotFound Bundle source was not found: no default package was specified when trust-manager was started; default CAs not available`,
		},
		"if Bundle references the configured default CAs, update targets with the CAs and ensure Bundle status references the configured default package version": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.DefaultJoinedCerts(),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle,
					gen.AppendBundleUsesDefaultPackage(),
					gen.SetBundleStatus(trustapi.BundleStatus{
						Conditions: []metav1.Condition{
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
			expError:                false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3, dummy.TestCertificate5)}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
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
			},
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
		"if Bundle removes reference to default package, remove version from Bundle Status and update targets": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				gen.SetBundleStatus(trustapi.BundleStatus{
					Conditions: []metav1.Condition{
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
			expError:                false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
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
			},
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
		"if Bundle switches from ConfigMap target no targets, remove ConfigMaps": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				func(b *trustapi.Bundle) {
					b.Spec.Target = &trustapi.BundleTarget{}
				},
				gen.SetBundleStatus(trustapi.BundleStatus{
					Conditions: []metav1.Condition{
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
			expError:                false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, nil, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-1", nil, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-2", nil, nil, nil, nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
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
			},
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
		"if Bundle switches from ConfigMap target to Secret target, remove ConfigMaps and create Secrets": {
			existingNamespaces: namespaces,
			existingConfigMaps: []client.Object{sourceConfigMap,
				targetConfigMap(
					trustNamespace,
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-1",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
				targetConfigMap(
					"ns-2",
					map[string]string{
						targetKey: dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3, dummy.TestCertificate5),
					},
					nil,
					ptr.To(targetKey),
					true, nil,
				),
			},
			existingSecrets: []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				func(b *trustapi.Bundle) {
					// swap target configmap for secret
					b.Spec.Target.ConfigMap, b.Spec.Target.Secret = b.Spec.Target.Secret, b.Spec.Target.ConfigMap
				},
				gen.SetBundleStatus(trustapi.BundleStatus{
					Conditions: []metav1.Condition{
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
			expError:                false,
			expPatches: []any{
				secretPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				secretPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, trustNamespace, nil, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-1", nil, nil, nil, nil),
				configMapPatch(baseBundle.Name, "ns-2", nil, nil, nil, nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
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
			},
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
		},
		"if Bundle has Secret target, and Secret targets are disabled, return an error": {
			disableSecretTargets: true,
			existingNamespaces:   namespaces,
			existingConfigMaps:   []client.Object{sourceConfigMap},
			existingSecrets:      []client.Object{sourceSecret},
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				func(b *trustapi.Bundle) {
					// copy configmap target to secret target
					b.Spec.Target.Secret = b.Spec.Target.ConfigMap
				},
				gen.SetBundleStatus(trustapi.BundleStatus{
					Conditions: []metav1.Condition{
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
			)},
			configureDefaultPackage: true,
			expError:                false,
			expPatches:              []any{},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "SecretTargetsDisabled",
						Message:            "Bundle has Secret targets but the feature is disabled",
						ObservedGeneration: bundleGeneration,
					},
				},
				DefaultCAPackageVersion: nil,
			},
			expEvent: `Warning SecretTargetsDisabled Bundle has Secret targets but the feature is disabled`,
		},
		"if Bundle has configmaps with expired cert, remove it": {
			configureDefaultPackage: false,
			existingNamespaces:      namespaces,
			existingConfigMaps: []client.Object{
				&corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{Kind: "ConfigMap", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:      sourceConfigMapName,
						Namespace: trustNamespace,
					},
					Data: map[string]string{
						"configmap-key": dummy.JoinCerts(dummy.TestExpiredCertificate, dummy.TestCertificate1),
					},
				},
			},
			existingSecrets: []client.Object{sourceSecret},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: `Normal Synced Successfully synced Bundle to all namespaces`,
			existingBundles: []client.Object{gen.BundleFrom(baseBundle,
				func(b *trustapi.Bundle) {
				},
				gen.SetBundleStatus(trustapi.BundleStatus{
					Conditions: []metav1.Condition{
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
			)},
			expError: false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, trustNamespace, map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3)}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3)}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.JoinCerts(dummy.TestCertificate2, dummy.TestCertificate1, dummy.TestCertificate3)}, nil, ptr.To(targetKey), nil),
			},
		},
		"if Bundle is configured to write to only a specific target namespaces and namespaceSelector is empty, then only write to these namespaces": {
			existingNamespaces: []client.Object{
				&corev1.Namespace{
					TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "ns-1"},
				},
				&corev1.Namespace{
					TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "ns-2"},
				},
				&corev1.Namespace{
					TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{Name: "outside-ns"},
				},
			},
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle, func(b *trustapi.Bundle) {
					b.Spec.Target.NamespaceSelector = nil
				}),
			},
			targetNamespaces: []string{"ns-1", "ns-2"},
			expError:         false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to all allowed namespaces",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to all allowed namespaces",
		},
		"if Bundle is configured to write to only a specific target namespaces and namespaceSelector is not empty, then write only to selected target namespaces": {
			existingNamespaces: []client.Object{
				&corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "ns-1",
						Labels: map[string]string{"trust-manager.io/namespace": "ns-1"},
					},
				},
				&corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "ns-2",
						Labels: map[string]string{"trust-manager.io/namespace": "ns-2"},
					},
				},
				&corev1.Namespace{
					TypeMeta: metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
					ObjectMeta: metav1.ObjectMeta{
						Name:   "outside-ns",
						Labels: map[string]string{"trust-manager.io/namespace": "outside-ns"},
					},
				},
			},
			existingConfigMaps: []client.Object{sourceConfigMap},
			existingSecrets:    []client.Object{sourceSecret},
			existingBundles: []client.Object{
				gen.BundleFrom(baseBundle, func(b *trustapi.Bundle) {
					b.Spec.Target.NamespaceSelector = &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "trust-manager.io/namespace",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"ns-1", "ns-2", "outside-ns"},
							},
						},
					}
				}),
			},
			targetNamespaces: []string{"ns-1", "ns-2"},
			expError:         false,
			expPatches: []any{
				configMapPatch(baseBundle.Name, "ns-1", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
				configMapPatch(baseBundle.Name, "ns-2", map[string]string{targetKey: dummy.DefaultJoinedCerts()}, nil, ptr.To(targetKey), nil),
			},
			expBundlePatch: &trustapi.BundleStatus{
				Conditions: []metav1.Condition{
					{
						Type:               trustapi.BundleConditionSynced,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Synced",
						Message:            "Successfully synced Bundle to allowed namespaces that match this label selector: trust-manager.io/namespace in (ns-1,ns-2,outside-ns)",
						ObservedGeneration: bundleGeneration,
					},
				},
			},
			expEvent: "Normal Synced Successfully synced Bundle to allowed namespaces that match this label selector: trust-manager.io/namespace in (ns-1,ns-2,outside-ns)",
		},
	}

	deepCopyArray := func(arr []client.Object) []client.Object {
		newArr := make([]client.Object, len(arr))
		for i, obj := range arr {
			newArr[i] = obj.DeepCopyObject().(client.Object)
		}
		return newArr
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fakeClient := fake.NewClientBuilder().
				WithScheme(test.Scheme).
				WithReturnManagedFields().
				WithObjects(deepCopyArray(tt.existingConfigMaps)...).
				WithObjects(deepCopyArray(tt.existingBundles)...).
				WithObjects(deepCopyArray(tt.existingNamespaces)...).
				WithObjects(deepCopyArray(tt.existingSecrets)...).
				WithStatusSubresource(deepCopyArray(tt.existingNamespaces)...).
				WithStatusSubresource(deepCopyArray(tt.existingBundles)...).
				Build()

			fakeRecorder := events.NewFakeRecorder(1)

			var (
				logMutex        sync.Mutex
				resourcePatches []any
			)

			_, ctx := ktesting.NewTestContext(t)
			opts := controller.Options{
				Namespace:            trustNamespace,
				SecretTargetsEnabled: !tt.disableSecretTargets,
				FilterExpiredCerts:   true,
			}
			b := &bundle{
				client:   fakeClient,
				recorder: fakeRecorder,
				clock:    fixedclock,
				Options:  opts,
				bundleBuilder: &source.BundleBuilder{
					Reader:  fakeClient,
					Options: opts,
				},
				targetReconciler: &target.Reconciler{
					Client: fakeClient,
					Cache:  fakeClient,
					PatchResourceOverwrite: func(ctx context.Context, obj any) error {
						logMutex.Lock()
						defer logMutex.Unlock()

						resourcePatches = append(resourcePatches, obj)
						return nil
					},
				},
			}

			if tt.configureDefaultPackage {
				b.bundleBuilder.DefaultPackage = testDefaultPackage.Clone()
			}

			b.Options.TargetNamespaces = tt.targetNamespaces
			statusPatch, err := b.reconcileBundle(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: bundleName}})
			if (err != nil) != tt.expError {
				t.Errorf("unexpected error, exp=%t got=%v", tt.expError, err)
			}

			assert.Equal(t, tt.expBundlePatch, statusPatch)

			var event string
			select {
			case event = <-fakeRecorder.Events:
			default:
			}
			assert.Equal(t, tt.expEvent, event)

			assert.ElementsMatch(t, tt.expPatches, resourcePatches, "unexpected objects patched")
		})
	}
}
