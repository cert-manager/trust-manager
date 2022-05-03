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

package gen

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
)

// BundleModifier is used to modify a Bundle object in-line. Intended for
// testing.
type BundleModifier func(*trustapi.Bundle)

// Bundle constructs a Bundle object with BundleModifiers which can be defined
// in-line. Intended for testing.
func Bundle(name string, mods ...BundleModifier) *trustapi.Bundle {
	bundle := &trustapi.Bundle{
		TypeMeta: metav1.TypeMeta{Kind: "Bundle", APIVersion: "trust.cert-manager.io/v1alpha1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Annotations: make(map[string]string),
			Labels:      make(map[string]string),
		},
	}
	for _, mod := range mods {
		mod(bundle)
	}
	return bundle
}

// BundleFrom deep copies a Bundle object and applies the given
// BundleModifiers.
func BundleFrom(bundle *trustapi.Bundle, mods ...BundleModifier) *trustapi.Bundle {
	bundle = bundle.DeepCopy()
	for _, mod := range mods {
		mod(bundle)
	}
	return bundle
}

// SetBundleStatus sets the Bundle object's status as a BundleModifier.
func SetBundleStatus(status trustapi.BundleStatus) BundleModifier {
	return func(bundle *trustapi.Bundle) {
		bundle.Status = status
	}
}

// SetResourceVersion sets the Bundle object's resource version as a
// BundleModifier.
func SetBundleResourceVersion(resourceVersion string) BundleModifier {
	return func(bundle *trustapi.Bundle) {
		bundle.ResourceVersion = resourceVersion
	}
}

// SetBundleTargetNamespaceSelector sets the Bundle object's spec target
// namespace selector.
func SetBundleTargetNamespaceSelectorLabelSelector(selector *metav1.LabelSelector) BundleModifier {
	return func(bundle *trustapi.Bundle) {
		bundle.Spec.Target.NamespaceSelector = &trustapi.NamespaceSelector{
			LabelSelector: selector,
		}
	}
}
