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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var BundleKind = "Bundle"

var BundleLabelKey = "trust.cert-manager.io/bundle"
var BundleHashAnnotationKey = "trust.cert-manager.io/hash"

// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".status.target.configMap.key",description="Bundle Target Key"
// +kubebuilder:printcolumn:name="Synced",type="string",JSONPath=`.status.conditions[?(@.type == "Synced")].status`,description="Bundle has been synced"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=`.status.conditions[?(@.type == "Synced")].reason`,description="Reason Bundle has Synced status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Timestamp Bundle was created"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +genclient

type Bundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired state of the Bundle resource.
	Spec BundleSpec `json:"spec"`

	// Status of the Bundle. This is set and managed automatically.
	// +optional
	Status BundleStatus `json:"status"`
}

// +kubebuilder:object:root=true
type BundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Bundle `json:"items"`
}

// BundleSepc defines the desired state of a Bundle.
type BundleSpec struct {
	// Sources is a set of references to data whose data will sync to the target.
	Sources []BundleSource `json:"sources"`

	// Target is the target location in all namespaces to sync source data to.
	Target BundleTarget `json:"target"`
}

// BundleSource is the set of sources whose data will be appended and synced to
// the BundleTarget in all Namespaces.
type BundleSource struct {
	// ConfigMap is a reference to a ConfigMap's `data` key, in the trust
	// Namespace.
	// +optional
	ConfigMap *SourceObjectKeySelector `json:"configMap,omitempty"`

	// Secret is a reference to a Secrets's `data` key, in the trust
	// Namespace.
	// +optional
	Secret *SourceObjectKeySelector `json:"secret,omitempty"`

	// InLine is a simple string to append as the source data.
	// +optional
	InLine *string `json:"inLine,omitempty"`

	// UseDefaultCAs, when true, requests the default CA bundle to be used as a source.
	// Default CAs are available if trust-manager was installed via Helm
	// or was otherwise set up to include a package-injecting init container by using the
	// "--default-package-location" flag when starting the trust-manager controller.
	// If default CAs were not configured at start-up, any request to use the default
	// CAs will fail.
	// The version of the default CA package which is used for a Bundle is stored in the
	// defaultCAPackageVersion field of the Bundle's status field.
	// +optional
	UseDefaultCAs *bool `json:"useDefaultCAs,omitempty"`
}

// BundleTarget is the target resource that the Bundle will sync all source
// data to.
type BundleTarget struct {
	// ConfigMap is the target ConfigMap in Namespaces that all Bundle source
	// data will be synced to.
	ConfigMap *KeySelector `json:"configMap,omitempty"`

	// Secret is the target Secret that all Bundle source data will be synced to.
	// Using Secrets as targets is only supported if enabled at trust-manager startup.
	// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
	Secret *KeySelector `json:"secret,omitempty"`

	// AdditionalFormats specifies any additional formats to write to the target
	// +optional
	AdditionalFormats *AdditionalFormats `json:"additionalFormats,omitempty"`

	// NamespaceSelector will, if set, only sync the target resource in
	// Namespaces which match the selector.
	// +optional
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`
}

// AdditionalFormats specifies any additional formats to write to the target
type AdditionalFormats struct {
	// JKS requests a JKS-formatted binary trust bundle to be written to the target.
	// The bundle is created with the hardcoded password "changeit".
	JKS *KeySelector `json:"jks,omitempty"`
	// PKCS12 requests a PKCS12-formatted binary trust bundle to be written to the target.
	// The bundle is created without a password.
	PKCS12 *KeySelector `json:"pkcs12,omitempty"`
}

// NamespaceSelector defines selectors to match on Namespaces.
type NamespaceSelector struct {
	// MatchLabels matches on the set of labels that must be present on a
	// Namespace for the Bundle target to be synced there.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// SourceObjectKeySelector is a reference to a source object and its `data` key
// in the trust Namespace.
type SourceObjectKeySelector struct {
	// Name is the name of the source object in the trust Namespace.
	Name string `json:"name"`

	// KeySelector is the key of the entry in the objects' `data` field to be referenced.
	KeySelector `json:",inline"`
}

// KeySelector is a reference to a key for some map data object.
type KeySelector struct {
	// Key is the key of the entry in the object's `data` field to be used.
	Key string `json:"key"`
}

// BundleStatus defines the observed state of the Bundle.
type BundleStatus struct {
	// List of status conditions to indicate the status of the Bundle.
	// Known condition types are `Bundle`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// DefaultCAPackageVersion, if set and non-empty, indicates the version information
	// which was retrieved when the set of default CAs was requested in the bundle
	// source. This should only be set if useDefaultCAs was set to "true" on a source,
	// and will be the same for the same version of a bundle with identical certificates.
	// +optional
	DefaultCAPackageVersion *string `json:"defaultCAVersion,omitempty"`
}

const (
	// BundleConditionSynced indicates that the Bundle has successfully synced
	// all source bundle data to the Bundle target in all Namespaces.
	BundleConditionSynced string = "Synced"
)
