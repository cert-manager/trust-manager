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

	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
)

// BundleModifier is used to modify a Bundle object in-line. Intended for
// testing.
type BundleModifier func(bundle *trustmanagerapi.ClusterBundle)

// Bundle constructs a Bundle object with BundleModifiers which can be defined
// in-line. Intended for testing.
func Bundle(name string, mods ...BundleModifier) *trustmanagerapi.ClusterBundle {
	bundle := &trustmanagerapi.ClusterBundle{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterBundle", APIVersion: "trust-manager.io/v1alpha2"},
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
func BundleFrom(bundle *trustmanagerapi.ClusterBundle, mods ...BundleModifier) *trustmanagerapi.ClusterBundle {
	bundle = bundle.DeepCopy()
	for _, mod := range mods {
		mod(bundle)
	}
	return bundle
}

// SetBundleStatus sets the Bundle object's status as a BundleModifier.
func SetBundleStatus(status trustmanagerapi.BundleStatus) BundleModifier {
	return func(bundle *trustmanagerapi.ClusterBundle) {
		bundle.Status = status
	}
}

func SetBundleKeyValueTarget(keyValue trustmanagerapi.KeyValueTarget) BundleModifier {
	return func(bundle *trustmanagerapi.ClusterBundle) {
		bundle.Spec.Target.ConfigMap = &keyValue
	}
}

// SetResourceVersion sets the Bundle object's resource version as a
// BundleModifier.
func SetBundleResourceVersion(resourceVersion string) BundleModifier {
	return func(bundle *trustmanagerapi.ClusterBundle) {
		bundle.ResourceVersion = resourceVersion
	}
}

// SetBundleTargetNamespaceSelectorMatchLabels sets the Bundle object's spec
// target namespace selector.
func SetBundleTargetNamespaceSelectorMatchLabels(matchLabels map[string]string) BundleModifier {
	return func(bundle *trustmanagerapi.ClusterBundle) {
		bundle.Spec.Target.NamespaceSelector = &metav1.LabelSelector{
			MatchLabels: matchLabels,
		}
	}
}

// IncludeDefaultCAs updates the bundle spec to include the default bundle package.
func IncludeDefaultCAs() BundleModifier {
	return func(bundle *trustmanagerapi.ClusterBundle) {
		bundle.Spec.DefaultCAs = &trustmanagerapi.DefaultCAsSource{
			Provider: trustmanagerapi.DefaultCAsProviderSystem,
		}
	}
}
