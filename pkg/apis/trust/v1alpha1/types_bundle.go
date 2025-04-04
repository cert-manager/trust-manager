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
// +kubebuilder:printcolumn:name="ConfigMap Target",type="string",JSONPath=".spec.target.configMap.key",description="Bundle ConfigMap Target Key"
// +kubebuilder:printcolumn:name="Secret Target",type="string",JSONPath=".spec.target.secret.key",description="Bundle Secret Target Key"
// +kubebuilder:printcolumn:name="Synced",type="string",JSONPath=`.status.conditions[?(@.type == "Synced")].status`,description="Bundle has been synced"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=`.status.conditions[?(@.type == "Synced")].reason`,description="Reason Bundle has Synced status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Timestamp Bundle was created"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +genclient
// +genclient:nonNamespaced

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

// BundleSpec defines the desired state of a Bundle.
type BundleSpec struct {
	// Sources is a set of references to data whose data will sync to the target.
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Sources []BundleSource `json:"sources"`

	// Target is the target location in all namespaces to sync source data to.
	Target BundleTarget `json:"target"`
}

// BundleSource is the set of sources whose data will be appended and synced to
// the BundleTarget in all Namespaces.
// +structType=atomic
type BundleSource struct {
	// ConfigMap is a reference (by name) to a ConfigMap's `data` key(s), or to a
	// list of ConfigMap's `data` key(s) using label selector, in the trust Namespace.
	// +optional
	ConfigMap *SourceObjectKeySelector `json:"configMap,omitempty"`

	// Secret is a reference (by name) to a Secret's `data` key(s), or to a
	// list of Secret's `data` key(s) using label selector, in the trust Namespace.
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
	// +optional
	ConfigMap Target `json:"configMap,omitempty"`

	// Secret is the target Secret that all Bundle source data will be synced to.
	// Using Secrets as targets is only supported if enabled at trust-manager startup.
	// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
	// +optional
	Secret Target `json:"secret,omitempty"`

	// NamespaceSelector will, if set, only sync the target resource in
	// Namespaces which match the selector.
	// +required
	NamespaceSelector metav1.LabelSelector `json:"namespaceSelector"`
}

// SourceObjectKeySelector is a reference to a source object and its `data` key(s)
// in the trust Namespace.
// +structType=atomic
type SourceObjectKeySelector struct {
	// Name is the name of the source object in the trust Namespace.
	// This field must be left empty when `selector` is set
	//+optional
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`

	// Selector is the label selector to use to fetch a list of objects. Must not be set
	// when `Name` is set.
	//+optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// Key of the entry in the object's `data` field to be used.
	//+optional
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`

	// IncludeAllKeys is a flag to include all keys in the object's `data` field to be used. False by default.
	// This field must not be true when `Key` is set.
	//+optional
	IncludeAllKeys bool `json:"includeAllKeys,omitempty"`
}

// Target is the specification of target key(s)
// +listType=map
// +listMapKey=key
// +kubebuilder:validation:MinItems=1
type Target []TargetKey

// TargetKey is the specification of a key in a target configmap/secret.
type TargetKey struct {
	// Key is the key of the entry in the object's `data` field to be used.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// Format defines the bundle format
	// +kubebuilder:validation:Enum=PEM;JKS;PKCS12
	// +kubebuilder:default=PEM
	//+optional
	Format *string `json:"format,omitempty"`

	// Password used to encrypt truststore if Format is JKS or PKCS12.
	// Default password for JKS truststore is `changeit`.
	// For PKCS#12 the truststore is by default created without a password.
	//+optional
	//+kubebuilder:validation:MinLength=1
	//+kubebuilder:validation:MaxLength=128
	Password *string `json:"password"`
}

// BundleStatus defines the observed state of the Bundle.
type BundleStatus struct {
	// List of status conditions to indicate the status of the Bundle.
	// Known condition types are `Bundle`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []BundleCondition `json:"conditions,omitempty"`

	// DefaultCAPackageVersion, if set and non-empty, indicates the version information
	// which was retrieved when the set of default CAs was requested in the bundle
	// source. This should only be set if useDefaultCAs was set to "true" on a source,
	// and will be the same for the same version of a bundle with identical certificates.
	// +optional
	DefaultCAPackageVersion *string `json:"defaultCAVersion,omitempty"`
}

// BundleCondition contains condition information for a Bundle.
type BundleCondition struct {
	// Type of the condition, known values are (`Synced`).
	// +kubebuilder:validation:Pattern=`^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])$`
	// +kubebuilder:validation:MaxLength=316
	Type string `json:"type"`

	// Status of the condition, one of True, False, Unknown.
	// +kubebuilder:validation:Enum=True;False;Unknown
	Status metav1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=date-time
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason is a brief machine-readable explanation for the condition's last
	// transition.
	// The value should be a CamelCase string.
	// This field may not be empty.
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?$`
	Reason string `json:"reason"`

	// Message is a human-readable description of the details of the last
	// transition, complementing reason.
	// +optional
	// +kubebuilder:validation:MaxLength=32768
	Message string `json:"message,omitempty"`

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Bundle.
	// +optional
	// +kubebuilder:validation:Minimum=0
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

const (
	// DefaultJKSPassword is the default password that Java uses; it's a Java convention to use this exact password.
	// Since we're not storing anything secret in the JKS files we generate, this password is not a meaningful security measure
	// but seems often to be expected by applications consuming JKS files
	DefaultJKSPassword = "changeit"
	// DefaultPKCS12Password is the empty string, that will create a password-less PKCS12 truststore.
	// Password-less PKCS is the new default Java truststore from Java 18.
	// By password-less, it means the certificates are not encrypted, and it contains no MacData for integrity check.
	DefaultPKCS12Password = ""

	// BundleConditionSynced indicates that the Bundle has successfully synced
	// all source bundle data to the Bundle target in all Namespaces.
	BundleConditionSynced string = "Synced"
)
