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

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var ClusterBundleKind = "ClusterBundle"

var BundleLabelKey = "trust-manager.io/bundle"
var BundleHashAnnotationKey = "trust-manager.io/hash"

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

type ClusterBundle struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata"`

	// spec represents the desired state of the ClusterBundle resource.
	// +optional
	Spec BundleSpec `json:"spec,omitzero"`

	// status of the ClusterBundle. This is set and managed automatically.
	// +optional
	Status BundleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true
type ClusterBundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []ClusterBundle `json:"items"`
}

// BundleSpec defines the desired state of a Bundle.
// +kubebuilder:validation:MinProperties=1
type BundleSpec struct {
	// sourceRefs is a list of references to resources whose data will be appended and synced into
	// the bundle target resources.
	// +listType=atomic
	// +optional
	// +kubebuilder:validation:MinItems=0
	// +kubebuilder:validation:MaxItems=100
	SourceRefs []BundleSourceRef `json:"sourceRefs,omitempty"`

	// defaultCAs configures the use of a default CA bundle as a trust source.
	// +optional
	DefaultCAs *DefaultCAsSource `json:"defaultCAs,omitempty"`

	// inLineCAs is a simple string to append as the source data.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1048576
	InLineCAs *string `json:"inLineCAs,omitempty"`

	// target is the target location in all namespaces to sync source data to.
	// +optional
	Target BundleTarget `json:"target,omitzero"`
}

// BundleSourceRef is a reference to source resource(s) whose data will be appended and synced into
// the bundle target resources.
// +structType=atomic
type BundleSourceRef struct {
	SourceReference `json:",inline"`

	// key specifies one or more keys in the object's data field to be used.
	// The "*" wildcard matches any sequence of characters within a key.
	// A value of "*" matches all entries in the data field.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z_.\-*]+$`
	Key string `json:"key,omitempty"`
}

// DefaultCAsSource configures the use of a default CA bundle as a trust source.
type DefaultCAsSource struct {
	// provider identifies the provider of the default CA bundle.
	//
	// Valid values:
	// - System: Uses the default CA package made available to trust-manager at startup.
	//      The default CA bundle is available only if trust-manager was installed with
	//		default CA support enabled, either via the Helm chart or by starting the
	//		trust-manager controller with the "--default-package-location" flag.
	//
	//		If no default CA package was configured at startup, specifying this source
	//		will result in reconciliation failure.
	//
	//		The version of the default CA package used for this Bundle is reported in
	//		status.defaultCAVersion.
	// - Disabled: No default CAs are used as sources.
	// +required
	// +kubebuilder:validation:Enum=System;Disabled
	Provider string `json:"provider,omitempty"`
}

// BundleTarget is the target resource that the Bundle will sync all source
// data to.
// +kubebuilder:validation:AtLeastOneOf=configMap;secret
type BundleTarget struct {
	// configMap is the target ConfigMap in Namespaces that all Bundle source data will be synced to.
	// +optional
	ConfigMap *KeyValueTarget `json:"configMap,omitempty"`

	// secret is the target Secret in Namespaces that all Bundle source data will be synced to.
	// Using Secrets as targets is only supported if enabled at trust-manager startup.
	// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
	// +optional
	Secret *KeyValueTarget `json:"secret,omitempty"`

	// namespaceSelector specifies the namespaces where target resources will be synced.
	// +required
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// PKCS12 specifies configs for target PKCS#12 files.
// +structType=atomic
// +kubebuilder:validation:MinProperties=0
type PKCS12 struct {
	// password for PKCS12 trust store.
	// By default, no password is used (password-less PKCS#12).
	// +optional
	// +kubebuilder:validation:MinLength=0
	// +kubebuilder:validation:MaxLength=128
	Password *string `json:"password,omitempty"`

	// profile specifies the certificate encryption algorithms and the HMAC algorithm
	// used to create the PKCS12 trust store.
	//
	// If provided, allowed values are:
	// `LegacyRC2`: Deprecated. Not supported by default in OpenSSL 3 or Java 20.
	// `LegacyDES`: Less secure algorithm. Use this option for maximal compatibility.
	// `Modern2023`: Secure algorithm. Use this option in case you have to always use secure algorithms (e.g. because of company policy).
	//
	// Default value is `LegacyDES`.
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

	ConfigMapKind string = "ConfigMap"

	SecretKind string = "Secret"

	DefaultCAsProviderDisabled string = "Disabled"
	DefaultCAsProviderSystem   string = "System"
)

// SourceReference is a reference to a source object.
// +structType=atomic
// +kubebuilder:validation:ExactlyOneOf=name;selector
type SourceReference struct {
	// kind is the kind of the source object.
	// +required
	// +kubebuilder:validation:Enum=ConfigMap;Secret
	Kind string `json:"kind,omitempty"`

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
}

// KeyValueTarget is the specification of key value target resources as ConfigMaps and Secrets.
type KeyValueTarget struct {
	// data is the specification of the object's `data` field.
	// +required
	// +listType=map
	// +listMapKey=key
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Data []TargetKeyValue `json:"data,omitempty"`

	// metadata is an optional set of labels and annotations to be copied to the target.
	// +optional
	Metadata *TargetMetadata `json:"metadata,omitempty"`
}

// GetAnnotations returns the annotations to be copied to the target or an empty map if there are no annotations.
func (t *KeyValueTarget) GetAnnotations() map[string]string {
	if t == nil || t.Metadata == nil {
		return nil
	}
	return t.Metadata.Annotations
}

// GetLabels returns the labels to be copied to the target or an empty map if there are no labels.
func (t *KeyValueTarget) GetLabels() map[string]string {
	if t == nil || t.Metadata == nil {
		return nil
	}
	return t.Metadata.Labels
}

// TargetKeyValue is the specification of a key with value in a key-value target resource.
// +structType=atomic
// +kubebuilder:validation:XValidation:rule="!has(self.password) || (has(self.format) && self.format == 'PKCS12')", reason=FieldValueForbidden, fieldPath=".password", message="may only be set when format is 'PKCS12'"
// +kubebuilder:validation:XValidation:rule="!has(self.profile) || (has(self.format) && self.format == 'PKCS12')", reason=FieldValueForbidden, fieldPath=".profile", message="may only be set when format is 'PKCS12'"
type TargetKeyValue struct {
	// key is the key of the entry in the object's `data` field to be used.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z_.\-]+$`
	Key string `json:"key,omitempty"`

	// format defines the format of the target value.
	// The default format is PEM.
	// +optional
	Format BundleFormat `json:"format,omitempty"`

	// PKCS12 specifies configs for PKCS#12 files.
	// May only be used when format is PKCS12.
	// +optional
	PKCS12 `json:",inline"`
}

// BundleFormat defines the trust bundle format.
// +kubebuilder:validation:Enum=PEM;PKCS12
type BundleFormat string

const (
	BundleFormatPEM BundleFormat = "PEM"

	BundleFormatPKCS12 BundleFormat = "PKCS12"
)

// TargetMetadata defines the default labels and annotations
// to be copied to the Kubernetes Secret or ConfigMap bundle targets.
// +kubebuilder:validation:MinProperties=1
type TargetMetadata struct {
	// annotations is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('trust-manager.io/'))", reason=FieldValueForbidden, message="must not use forbidden domains as prefixes (e.g., trust-manager.io)"
	Annotations map[string]string `json:"annotations,omitempty"`

	// labels is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:MinProperties=1
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('trust-manager.io/'))", reason=FieldValueForbidden, message="must not use forbidden domains as prefixes (e.g., trust-manager.io)"
	Labels map[string]string `json:"labels,omitempty"`
}

// BundleStatus defines the observed state of the Bundle.
// +kubebuilder:validation:MinProperties=1
type BundleStatus struct {
	// conditions represent the latest available observations of the ClusterBundle's current state.
	// +listType=map
	// +listMapKey=type
	// +optional
	// +kubebuilder:validation:MinItems=0
	// +kubebuilder:validation:MaxItems=10
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// defaultCAVersion is the version of the default CA package used for this ClusterBundle
	// when resolving default CAs, if applicable.
	// This field is populated only when spec.includeDefaultCAs is set to true.
	// ClusterBundles resolved from identical sets of default CA certificates will report
	// the same defaultCAVersion value.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	DefaultCAPackageVersion *string `json:"defaultCAVersion,omitempty"`
}

const (
	// DefaultPKCS12Password is the empty string, that will create a password-less PKCS12 truststore.
	// Password-less PKCS is the new default Java truststore from Java 18.
	// By password-less, it means the certificates are not encrypted, and it contains no MacData for integrity check.
	DefaultPKCS12Password = ""

	// BundleConditionSynced indicates that the Bundle has successfully synced
	// all source bundle data to the Bundle target in all Namespaces.
	BundleConditionSynced string = "Synced"

	BundleMigratedAnnotation string = "trust-manager.io/migrated"
)
