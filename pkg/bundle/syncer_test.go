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
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
)

func Test_syncTarget(t *testing.T) {
	const (
		bundleName = "test-bundle"
		namespace  = "test-namespace"
		key        = "key"
		data       = "data"
	)

	tests := map[string]struct {
		object         runtime.Object
		expNeedsUpdate bool
	}{
		"if object doesn't exist, expect update": {
			object:         nil,
			expNeedsUpdate: true,
		},
		"if object exists but without data or owner, expect update": {
			object:         &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: namespace}},
			expNeedsUpdate: true,
		},
		"if object exists with data but no owner, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName, Namespace: namespace},
				Data:       map[string]string{key: data},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but no data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundleName,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
					},
				},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong data, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundleName,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
					},
				},
				Data: map[string]string{key: "wrong data"},
			},
			expNeedsUpdate: true,
		},
		"if object exists with owner but wrong key, expect update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundleName,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
					},
				},
				Data: map[string]string{"wrong key": data},
			},
			expNeedsUpdate: true,
		},
		"if object exists with correct data, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundleName,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
					},
				},
				Data: map[string]string{key: data},
			},
			expNeedsUpdate: false,
		},
		"if object exists with correct data and some extra data and owner, expect no update": {
			object: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      bundleName,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               bundleName,
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
						{
							Kind:               "Bundle",
							APIVersion:         "trust.cert-manager.io/v1alpha1",
							Name:               "another-bundle",
							Controller:         pointer.Bool(true),
							BlockOwnerDeletion: pointer.Bool(true),
						},
					},
				},
				Data: map[string]string{key: data, "another-key": "another-data"},
			},
			expNeedsUpdate: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			clientBuilder := fakeclient.NewClientBuilder().
				WithScheme(trustapi.GlobalScheme)
			if test.object != nil {
				clientBuilder.WithRuntimeObjects(test.object)
			}
			fakeclient := clientBuilder.Build()

			b := &bundle{client: fakeclient}

			needsUpdate, err := b.syncTarget(context.TODO(), klogr.New(), &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: bundleName},
				Spec:       trustapi.BundleSpec{Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{key}}},
			}, namespace, data)
			if err != nil {
				t.Errorf("unexpected error: %s", err)
			}
			if needsUpdate != test.expNeedsUpdate {
				t.Errorf("unexpected needsUpdate, exp=%t got=%t", test.expNeedsUpdate, needsUpdate)
			}

			var configMap corev1.ConfigMap
			if err := fakeclient.Get(context.TODO(), client.ObjectKey{Namespace: namespace, Name: bundleName}, &configMap); err != nil {
				t.Errorf("unexpected error: %s", err)
			}

			if configMap.Data[key] != data {
				t.Errorf("unexpected data on ConfigMap: exp=%s:%s got=%v", key, data, configMap.Data)
			}
			if configMap.Data[key] != data {
				t.Errorf("unexpected data on ConfigMap: exp=%s:%s got=%v", key, data, configMap.Data)
			}

			exptedOwnerReference := metav1.OwnerReference{
				Kind:               "Bundle",
				APIVersion:         "trust.cert-manager.io/v1alpha1",
				Name:               bundleName,
				Controller:         pointer.Bool(true),
				BlockOwnerDeletion: pointer.Bool(true),
			}
			if !apiequality.Semantic.DeepEqual(configMap.OwnerReferences[0], exptedOwnerReference) {
				t.Errorf("unexpected owner reference: exp=%v got=%v", exptedOwnerReference, configMap.OwnerReferences)
			}
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
		"if no sources defined, should return no data": {
			bundle:           &trustapi.Bundle{},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         false,
			expNotFoundError: false,
		},
		"if single InLine source defined with newlines, should trim and return": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{InLine: pointer.String("\n\n\nA\n\nB\n\n\n")},
			}}},
			objects:          []runtime.Object{},
			expData:          "A\n\nB\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if single ConfigMap source which doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
			}}},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source whose key doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
			}}},
			objects:          []runtime.Object{&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "configmap"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single ConfigMap source, return data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
			}}},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": "\n\n\nA\n\nB\n\n"},
			}},
			expData:          "A\n\nB\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if ConfigMap and InLine source, return appended data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
				{InLine: pointer.String("\n\n\nC\n\nD\n\n\n")},
			}}},
			objects: []runtime.Object{&corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
				Data:       map[string]string{"key": "\n\n\nA\n\nB\n\n"},
			}},
			expData:          "A\n\nB\nC\n\nD\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if single Secret source exists which doesn't exist, should return not found error": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects:          []runtime.Object{},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source whose key doesn't exist, return notFoundError": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects:          []runtime.Object{&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "secret"}}},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if single Secret source, return data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte("\n\n\nA\n\nB\n\n")},
			}},
			expData:          "A\n\nB\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret and InLine source, return appended data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
				{InLine: pointer.String("\n\n\nC\n\nD\n\n\n")},
			}}},
			objects: []runtime.Object{&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "secret"},
				Data:       map[string][]byte{"key": []byte("\n\n\nA\n\nB\n\n")},
			}},
			expData:          "A\n\nB\nC\n\nD\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if Secret, ConfigmMap and InLine source, return appended data": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
				{InLine: pointer.String("\n\n\nC\n\nD\n\n\n")},
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": "\n\n\nA\n\nB\n\n"},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret"},
					Data:       map[string][]byte{"key": []byte("\n\n\nE\n\nF\n\n")},
				},
			},
			expData:          "A\n\nB\nC\n\nD\nE\n\nF\n",
			expError:         false,
			expNotFoundError: false,
		},
		"if source Secret exists, but not ConfigMap, return not found error": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "configmap"},
					Data:       map[string]string{"key": "\n\n\nA\n\nB\n\n"},
				},
			},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
		"if source ConfigMap exists, but not Secret, return not found error": {
			bundle: &trustapi.Bundle{Spec: trustapi.BundleSpec{Sources: []trustapi.BundleSource{
				{ConfigMap: &trustapi.SourceObjectKeySelector{"configmap", trustapi.KeySelector{"key"}}},
				{Secret: &trustapi.SourceObjectKeySelector{"secret", trustapi.KeySelector{"key"}}},
			}}},
			objects: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "secret"},
					Data:       map[string][]byte{"key": []byte("\n\n\nA\n\nB\n\n")},
				},
			},
			expData:          "",
			expError:         true,
			expNotFoundError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithRuntimeObjects(test.objects...).
				WithScheme(trustapi.GlobalScheme).
				Build()

			b := &bundle{client: fakeclient}

			data, err := b.buildSourceBundle(context.TODO(), test.bundle)

			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}
			if errors.As(err, &notFoundError{}) != test.expNotFoundError {
				t.Errorf("unexpected notFoundError, exp=%t got=%v", test.expNotFoundError, err)
			}

			if data != test.expData {
				t.Errorf("unexpected data, exp=%q got=%q", test.expData, data)
			}
		})
	}
}
