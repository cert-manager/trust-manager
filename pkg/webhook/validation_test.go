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

package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

func Test_validate(t *testing.T) {
	tests := map[string]struct {
		bundle      runtime.Object
		expErr      *string
		expWarnings admission.Warnings
	}{
		"if the object being validated is not a Bundle, return an error": {
			bundle: &corev1.Pod{},
			expErr: ptr.To("expected a Bundle, but got a *v1.Pod"),
		},
		"no sources, no target": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources"), "must define at least one source"),
				field.Invalid(field.NewPath("spec", "target"), trustapi.BundleTarget{}, "must define at least one target"),
			}.ToAggregate().Error()),
		},
		"sources with multiple types defined in items": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{
							ConfigMap: &trustapi.SourceObjectKeySelector{Name: "test", Key: "test"},
							InLine:    ptr.To("test"),
						},
						{InLine: ptr.To("test")},
						{
							ConfigMap: &trustapi.SourceObjectKeySelector{Name: "test", Key: "test"},
							Secret:    &trustapi.SourceObjectKeySelector{Name: "test", Key: "test"},
						},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources", "[0]"), "must define exactly one source type for each item but found 2 defined types"),
				field.Forbidden(field.NewPath("spec", "sources", "[2]"), "must define exactly one source type for each item but found 2 defined types"),
			}.ToAggregate().Error()),
		},
		"empty source with no defined types": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources", "[0]"), "must define exactly one source type for each item but found 0 defined types"),
				field.Forbidden(field.NewPath("spec", "sources"), "must define at least one source"),
			}.ToAggregate().Error()),
		},
		"useDefaultCAs false, with no other defined sources": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{
							UseDefaultCAs: ptr.To(false),
						},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources"), "must define at least one source"),
			}.ToAggregate().Error()),
		},
		"useDefaultCAs requested twice": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{
							UseDefaultCAs: ptr.To(true),
						},
						{
							UseDefaultCAs: ptr.To(true),
						},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources"), "must request default CAs either once or not at all but got 2 requests"),
			}.ToAggregate().Error()),
		},
		"useDefaultCAs requested three times": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{
							UseDefaultCAs: ptr.To(true),
						},
						{
							UseDefaultCAs: ptr.To(false),
						},
						{
							UseDefaultCAs: ptr.To(true),
						},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Forbidden(field.NewPath("spec", "sources"), "must request default CAs either once or not at all but got 3 requests"),
			}.ToAggregate().Error()),
		},
		"sources names, selectors and keys are empty": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "", Key: ""}},
						{InLine: ptr.To("test")},
						{Secret: &trustapi.SourceObjectKeySelector{Name: "", Key: ""}},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "sources", "[0]", "configMap"), "name: ' ', selector: nil", "must validate one and only one schema (oneOf): [name, selector]. Found none valid"),
				field.Invalid(field.NewPath("spec", "sources", "[0]", "configMap"), "key: ' ', includeAllKeys: false", "source configMap key must be defined when includeAllKeys is false"),
				field.Invalid(field.NewPath("spec", "sources", "[2]", "secret"), "name: ' ', selector: nil", "must validate one and only one schema (oneOf): [name, selector]. Found none valid"),
				field.Invalid(field.NewPath("spec", "sources", "[2]", "secret"), "key: ' ', includeAllKeys: false", "source secret key must be defined when includeAllKeys is false"),
			}.ToAggregate().Error()),
		},
		"sources names and selectors are both set": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "some-config-map", Selector: &metav1.LabelSelector{}, Key: "test"}},
						{InLine: ptr.To("test")},
						{Secret: &trustapi.SourceObjectKeySelector{Name: "some-secret", Selector: &metav1.LabelSelector{}, Key: "test"}},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "sources", "[0]", "configMap"), "name: some-config-map, selector: {}", "must validate one and only one schema (oneOf): [name, selector]. Found both set"),
				field.Invalid(field.NewPath("spec", "sources", "[2]", "secret"), "name: some-secret, selector: {}", "must validate one and only one schema (oneOf): [name, selector]. Found both set"),
			}.ToAggregate().Error()),
		},
		"sources key is set and includeAllKeys is true": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "some-config-map", Key: "test", IncludeAllKeys: true}},
						{InLine: ptr.To("test")},
						{Secret: &trustapi.SourceObjectKeySelector{Name: "some-secret", Key: "test", IncludeAllKeys: true}},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: "test"}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "sources", "[0]", "configMap"), "key: test, includeAllKeys: true", "source configMap key cannot be defined when includeAllKeys is true"),
				field.Invalid(field.NewPath("spec", "sources", "[2]", "secret"), "key: test, includeAllKeys: true", "source secret key cannot be defined when includeAllKeys is true"),
			}.ToAggregate().Error()),
		},
		"target configMap key not defined": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("test")},
					},
					Target: trustapi.BundleTarget{ConfigMap: &trustapi.KeySelector{Key: ""}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "target", "configMap", "key"), "", "target configMap key must be defined"),
			}.ToAggregate().Error()),
		},
		"target secret key not defined": {
			bundle: &trustapi.Bundle{
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("test")},
					},
					Target: trustapi.BundleTarget{Secret: &trustapi.KeySelector{Key: ""}},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "target", "secret", "key"), "", "target secret key must be defined"),
			}.ToAggregate().Error()),
		},
		"invalid namespace selector": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bundle-1"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("test-1")},
					},
					Target: trustapi.BundleTarget{
						ConfigMap: &trustapi.KeySelector{Key: "test-1"},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"@@@@": ""},
						},
					},
				},
				Status: trustapi.BundleStatus{
					Conditions: []trustapi.BundleCondition{
						{
							Type:   "A",
							Reason: "C",
						},
					},
				},
			},
			expErr: ptr.To(field.ErrorList{
				field.Invalid(field.NewPath("spec", "target", "namespaceSelector", "matchLabels"), map[string]string{"@@@@": ""}, `key: Invalid value: "@@@@": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')`),
			}.ToAggregate().Error()),
		},
		"a Bundle with a duplicate target JKS key should fail validation and return a denied response": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("foo")},
					},
					Target: trustapi.BundleTarget{
						AdditionalFormats: &trustapi.AdditionalFormats{
							JKS: &trustapi.JKS{
								KeySelector: trustapi.KeySelector{
									Key: "bar",
								},
							},
						},
						ConfigMap: &trustapi.KeySelector{
							Key: "bar",
						},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			expErr: ptr.To("spec.target.additionalFormats.jks.key: Invalid value: \"bar\": key must be unique in target configMap"),
		},
		"a Bundle with a duplicate target PKCS12 key should fail validation and return a denied response": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("foo")},
					},
					Target: trustapi.BundleTarget{
						AdditionalFormats: &trustapi.AdditionalFormats{
							PKCS12: &trustapi.PKCS12{
								KeySelector: trustapi.KeySelector{
									Key: "bar",
								},
							},
						},
						ConfigMap: &trustapi.KeySelector{
							Key: "bar",
						},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			expErr: ptr.To("spec.target.additionalFormats.pkcs12.key: Invalid value: \"bar\": key must be unique in target configMap"),
		},
		"valid Bundle": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bundle-1"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("test-1")},
					},
					Target: trustapi.BundleTarget{
						ConfigMap: &trustapi.KeySelector{Key: "test-1"},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
				Status: trustapi.BundleStatus{
					Conditions: []trustapi.BundleCondition{
						{
							Type:   "A",
							Reason: "B",
						},
						{
							Type:   "B",
							Reason: "C",
						},
					},
				},
			},
			expErr: nil,
		},
		"valid Bundle with JKS": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("foo")},
					},
					Target: trustapi.BundleTarget{
						AdditionalFormats: &trustapi.AdditionalFormats{
							JKS: &trustapi.JKS{
								KeySelector: trustapi.KeySelector{
									Key: "bar.jks",
								},
							},
						},
						ConfigMap: &trustapi.KeySelector{
							Key: "bar",
						},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			expErr: nil,
		},
		"valid Bundle with PKCS12": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: ptr.To("foo")},
					},
					Target: trustapi.BundleTarget{
						AdditionalFormats: &trustapi.AdditionalFormats{
							PKCS12: &trustapi.PKCS12{
								KeySelector: trustapi.KeySelector{
									Key: "bar.p12",
								},
							},
						},
						ConfigMap: &trustapi.KeySelector{
							Key: "bar",
						},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			expErr: nil,
		},
		"valid Bundle including all keys": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bundle-1"},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{Name: "some-config-map", IncludeAllKeys: true}},
						{Secret: &trustapi.SourceObjectKeySelector{Name: "some-secret", IncludeAllKeys: true}},
					},
					Target: trustapi.BundleTarget{
						ConfigMap: &trustapi.KeySelector{Key: "test-1"},
						NamespaceSelector: &trustapi.NamespaceSelector{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			expErr: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log, _ := ktesting.NewTestContext(t)
			v := &validator{log: log}
			gotWarnings, gotErr := v.validate(test.bundle)
			if test.expErr == nil && gotErr != nil {
				t.Errorf("got an unexpected error: %v", gotErr)
			} else if test.expErr != nil && (gotErr == nil || *test.expErr != gotErr.Error()) {
				t.Errorf("wants error: %v got: %v", *test.expErr, gotErr)
			}
			assert.Equal(t, test.expWarnings, gotWarnings)

		})
	}
}

func Test_validate_update(t *testing.T) {
	tests := map[string]struct {
		oldBundle   runtime.Object
		newBundle   runtime.Object
		expErr      *string
		expWarnings admission.Warnings
	}{
		"if the target configmap is removed during update": {
			oldBundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Target: trustapi.BundleTarget{
						ConfigMap: &trustapi.KeySelector{
							Key: "bar",
						},
					},
				},
			},
			newBundle: &trustapi.Bundle{},
			expErr:    ptr.To("spec.target.configmap: Invalid value: \"\": target configMap removal is not allowed"),
		},
		"if the target secret is removed during update": {
			oldBundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{Name: "testing"},
				Spec: trustapi.BundleSpec{
					Target: trustapi.BundleTarget{
						Secret: &trustapi.KeySelector{
							Key: "bar",
						},
					},
				},
			},
			newBundle: &trustapi.Bundle{},
			expErr:    ptr.To("spec.target.secret: Invalid value: \"\": target secret removal is not allowed"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			log, ctx := ktesting.NewTestContext(t)
			v := &validator{log: log}
			gotWarnings, gotErr := v.ValidateUpdate(ctx, test.oldBundle, test.newBundle)
			if test.expErr == nil && gotErr != nil {
				t.Errorf("got an unexpected error: %v", gotErr)
			} else if test.expErr != nil && (gotErr == nil || *test.expErr != gotErr.Error()) {
				t.Errorf("wants error: %v got: %v", *test.expErr, gotErr)
			}
			assert.Equal(t, test.expWarnings, gotWarnings)

		})
	}
}
