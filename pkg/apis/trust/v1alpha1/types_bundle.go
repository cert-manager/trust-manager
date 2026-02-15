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
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata"`

	// spec represents the desired state of the Bundle resource.
	// +required
	Spec BundleSpec `json:"spec,omitzero"`

	// status of the Bundle. This is set and managed automatically.
	// +optional
	Status BundleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type BundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Bundle `json:"items"`
}

// BundleSpec defines the desired state of a Bundle.
type BundleSpec struct {
	// sources is a set of references to data whose data will sync to the target.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=100
	Sources []BundleSource `json:"sources,omitempty"`

	// target is the target location in all namespaces to sync source data to.
	// +optional
	Target BundleTarget `json:"target,omitzero"`
}

// BundleSource is the set of sources whose data will be appended and synced to
// the BundleTarget in all Namespaces.
// +structType=atomic
// +kubebuilder:validation:ExactlyOneOf=configMap;secret;inLine;useDefaultCAs
type BundleSource struct {
	// configMap is a reference (by name) to a ConfigMap's `data` key(s), or to a
	// list of ConfigMap's `data` key(s) using label selector, in the trust namespace.
	// +optional
	ConfigMap *SourceObjectKeySelector `json:"configMap,omitempty"`

	// secret is a reference (by name) to a Secret's `data` key(s), or to a
	// list of Secret's `data` key(s) using label selector, in the trust namespace.
	// +optional
	Secret *SourceObjectKeySelector `json:"secret,omitempty"`

	// inLine is a simple string to append as the source data.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1048576
	InLine *string `json:"inLine,omitempty"`

	// useDefaultCAs indicates whether the default CA bundle should be used as a source.
	// The default CA bundle is available only if trust-manager was installed with
	// default CA support enabled, either via the Helm chart or by starting the
	// trust-manager controller with the "--default-package-location" flag.
	// If default CA support was not enabled at startup, setting this field to true
	// will result in reconciliation failure.
	// The version of the default CA package used for this Bundle is reported in
	// status.defaultCAVersion.
	// +optional
	UseDefaultCAs *bool `json:"useDefaultCAs,omitempty"`
}

// BundleTarget is the target resource that the Bundle will sync all source
// data to.
// +kubebuilder:validation:AtLeastOneOf=configMap;secret
type BundleTarget struct {
	// configMap is the target ConfigMap in Namespaces that all Bundle source
	// data will be synced to.
	// +optional
	ConfigMap *TargetTemplate `json:"configMap,omitempty"`

	// secret is the target Secret that all Bundle source data will be synced to.
	// Using Secrets as targets is only supported if enabled at trust-manager startup.
	// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
	// +optional
	Secret *TargetTemplate `json:"secret,omitempty"`

	// additionalFormats specifies any additional formats to write to the target
	// +optional
	AdditionalFormats *AdditionalFormats `json:"additionalFormats,omitempty"`

	// namespaceSelector will, if set, only sync the target resource in
	// Namespaces which match the selector.
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// AdditionalFormats specifies any additional formats to write to the target
// +kubebuilder:validation:AtLeastOneOf=jks;pkcs12
type AdditionalFormats struct {
	// jks requests a JKS-formatted binary trust bundle to be written to the target.
	// The bundle has "changeit" as the default password.
	// For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
	// Format is deprecated: Writing JKS is subject for removal. Please migrate to PKCS12.
	// PKCS#12 trust stores created by trust-manager are compatible with Java.
	// +optional
	JKS *JKS `json:"jks,omitempty"`
	// pkcs12 requests a PKCS12-formatted binary trust bundle to be written to the target.
	//
	// The bundle is by default created without a password.
	// For more information refer to this link https://cert-manager.io/docs/faq/#keystore-passwords
	// +optional
	PKCS12 *PKCS12 `json:"pkcs12,omitempty"`
}

// JKS specifies additional target JKS files
// +structType=atomic
// +kubebuilder:validation:MinProperties=1
type JKS struct {
	KeySelector `json:",inline"`

	// password for JKS trust store
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:default=changeit
	Password *string `json:"password,omitempty"`
}

// PKCS12 specifies additional target PKCS#12 files
// +structType=atomic
// +kubebuilder:validation:MinProperties=1
type PKCS12 struct {
	KeySelector `json:",inline"`

	// password for PKCS12 trust store
	// +optional
	// +kubebuilder:validation:MinLength=0
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:default=""
	Password *string `json:"password,omitempty"`

	// profile specifies the certificate encryption algorithms and the HMAC algorithm
	// used to create the PKCS12 trust store.
	//
	// If provided, allowed values are:
	// `LegacyRC2`: Deprecated. Not supported by default in OpenSSL 3 or Java 20.
	// `LegacyDES`: Less secure algorithm. Use this option for maximal compatibility.
	// `Modern2023`: Secure algorithm. Use this option in case you have to always use secure algorithms (e.g. because of company policy).
	//
	// Default value is `LegacyRC2` for backward compatibility.
	// +optional
	Profile PKCS12Profile `json:"profile,omitempty"`
}

// +kubebuilder:validation:Enum=LegacyRC2;LegacyDES;Modern2023
type PKCS12Profile string

const (
	// see: https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#LegacyRC2
	LegacyRC2PKCS12Profile PKCS12Profile = "LegacyRC2"

	// see: https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#LegacyDES
	LegacyDESPKCS12Profile PKCS12Profile = "LegacyDES"

	// see: https://pkg.go.dev/software.sslmate.com/src/go-pkcs12#Modern2023
	Modern2023PKCS12Profile PKCS12Profile = "Modern2023"
)

// SourceObjectKeySelector is a reference to a source object and its `data` key(s)
// in the trust namespace.
// +structType=atomic
// +kubebuilder:validation:ExactlyOneOf=name;selector
type SourceObjectKeySelector struct {
	// name is the name of the source object in the trust namespace.
	// This field must be left empty when `selector` is set
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`

	// selector is the label selector to use to fetch a list of objects. Must not be set
	// when `name` is set.
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`

	// key of the entry in the object's `data` field to be used.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`

	// includeAllKeys is a flag to include all keys in the object's `data` field to be used. False by default.
	// This field must not be true when `key` is set.
	// +optional
	IncludeAllKeys *bool `json:"includeAllKeys,omitempty"`
}

// TargetTemplate defines the form of the Kubernetes Secret or ConfigMap bundle targets.
type TargetTemplate struct {
	// key is the key of the entry in the object's `data` field to be used.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`

	// metadata is an optional set of labels and annotations to be copied to the target.
	// +optional
	Metadata *TargetMetadata `json:"metadata,omitempty"`
}

// GetAnnotations returns the annotations to be copied to the target or an empty map if there are no annotations.
func (t *TargetTemplate) GetAnnotations() map[string]string {
	if t == nil || t.Metadata == nil {
		return nil
	}
	return t.Metadata.Annotations
}

// GetLabels returns the labels to be copied to the target or an empty map if there are no labels.
func (t *TargetTemplate) GetLabels() map[string]string {
	if t == nil || t.Metadata == nil {
		return nil
	}
	return t.Metadata.Labels
}

// KeySelector is a reference to a key for some map data object.
type KeySelector struct {
	// key is the key of the entry in the object's `data` field to be used.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Key string `json:"key,omitempty"`
}

// TargetMetadata defines the default labels and annotations
// to be copied to the Kubernetes Secret or ConfigMap bundle targets.
// +kubebuilder:validation:MinProperties=1
type TargetMetadata struct {
	// annotations is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:MinProperties=1
	Annotations map[string]string `json:"annotations,omitempty"`

	// labels is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:MinProperties=1
	Labels map[string]string `json:"labels,omitempty"`
}

// BundleStatus defines the observed state of the Bundle.
// +kubebuilder:validation:MinProperties=1
type BundleStatus struct {
	// conditions represent the latest available observations of the Bundle's current state.
	// +listType=map
	// +listMapKey=type
	// +optional
	// +kubebuilder:validation:MinItems=0
	// +kubebuilder:validation:MaxItems=10
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// defaultCAVersion is the version of the default CA package used when resolving
	// the default CA source(s) for this Bundle (for example, when any source has
	// useDefaultCAs set to true), if applicable.
	// Bundles resolved from identical sets of default CA certificates will report
	// the same defaultCAVersion value.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	DefaultCAPackageVersion *string `json:"defaultCAVersion,omitempty"`
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
	// BundleConditionDeprecated is a condition type used in migration from Bundle to ClusterBundle.
	BundleConditionDeprecated string = "Deprecated"
	// BundleConditionMigrated indicates that the Bundle has been successfully migrated
	// to ClusterBundle by user. The user has taken ownership of the migrated ClusterBundle,
	// and the obsolete Bundle can now be safely deleted by user.
	BundleConditionMigrated string = "Migrated"
)
