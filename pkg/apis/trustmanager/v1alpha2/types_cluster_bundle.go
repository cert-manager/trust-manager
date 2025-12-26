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
	// +optional
	metav1.ObjectMeta `json:"metadata"`

	// Desired state of the Bundle resource.
	Spec BundleSpec `json:"spec"`

	// Status of the Bundle. This is set and managed automatically.
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
type BundleSpec struct {
	// Sources is a set of references to data whose data will sync to the target.
	// +listType=atomic
	// +optional
	// +kubebuilder:validation:MinItems=0
	// +kubebuilder:validation:MaxItems=100
	Sources []BundleSource `json:"sources,omitempty"`

	// IncludeDefaultCAs, when true, requests the default CA bundle to be used as a source.
	// Default CAs are available if trust-manager was installed via Helm
	// or was otherwise set up to include a package-injecting init container by using the
	// "--default-package-location" flag when starting the trust-manager controller.
	// If default CAs were not configured at start-up, any request to use the default
	// CAs will fail.
	// The version of the default CA package which is used for a Bundle is stored in the
	// defaultCAPackageVersion field of the Bundle's status field.
	// +optional
	IncludeDefaultCAs *bool `json:"includeDefaultCAs,omitempty"`

	// InLine is a simple string to append as the source data.
	// +optional
	InLineCAs *string `json:"inLineCAs,omitempty"`

	// Target is the target location in all namespaces to sync source data to.
	// +optional
	Target BundleTarget `json:"target,omitzero"`

	// Use only CAs certificates in a resulting Bundle
	// +optional
	UseCACertsOnly *bool `json:"useCACertsOnly,omitempty"`
}

// BundleSource is the set of sources whose data will be appended and synced to
// the BundleTarget in all Namespaces.
// +structType=atomic
type BundleSource struct {
	SourceReference `json:",inline"`

	// Key(s) of the entry in the object's `data` field to be used.
	// Wildcards "*" in Key matches any sequence characters.
	// A Key containing only "*" will match all data fields.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z_.\-*]+$`
	Key string `json:"key"`
}

// BundleTarget is the target resource that the Bundle will sync all source
// data to.
// +kubebuilder:validation:XValidation:rule="[has(self.configMap), has(self.secret)].exists(x,x)", message="any of the following fields must be provided: [configMap, secret]"
type BundleTarget struct {
	// ConfigMap is the target ConfigMap in Namespaces that all Bundle source data will be synced to.
	// +optional
	ConfigMap *KeyValueTarget `json:"configMap,omitempty"`

	// Secret is the target Secret in Namespaces that all Bundle source data will be synced to.
	// Using Secrets as targets is only supported if enabled at trust-manager startup.
	// By default, trust-manager has no permissions for writing to secrets and can only read secrets in the trust namespace.
	// +optional
	Secret *KeyValueTarget `json:"secret,omitempty"`

	// NamespaceSelector specifies the namespaces where target resources will be synced.
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`
}

// PKCS12 specifies configs for target PKCS#12 files.
// +structType=atomic
type PKCS12 struct {
	// Password for PKCS12 trust store.
	// By default, no password is used (password-less PKCS#12).
	//+optional
	//+kubebuilder:validation:MaxLength=128
	Password *string `json:"password,omitempty"`

	// Profile specifies the certificate encryption algorithms and the HMAC algorithm
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
)

// SourceReference is a reference to a source object.
// +structType=atomic
// +kubebuilder:validation:XValidation:rule="[has(self.name), has(self.selector)].exists_one(x,x)", message="exactly one of the following fields must be provided: [name, selector]"
type SourceReference struct {
	// Kind is the kind of the source object.
	// +kubebuilder:validation:Enum=ConfigMap;Secret
	Kind string `json:"kind"`

	// Name is the name of the source object in the trust Namespace.
	// This field must be left empty when `selector` is set
	//+optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name,omitempty"`

	// Selector is the label selector to use to fetch a list of objects. Must not be set
	// when `Name` is set.
	//+optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// KeyValueTarget is the specification of key value target resources as ConfigMaps and Secrets.
type KeyValueTarget struct {
	// Data is the specification of the object's `data` field.
	// +listType=map
	// +listMapKey=key
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	Data []TargetKeyValue `json:"data"`

	// Metadata is an optional set of labels and annotations to be copied to the target.
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
	// Key is the key of the entry in the object's `data` field to be used.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[0-9A-Za-z_.\-]+$`
	Key string `json:"key"`

	// Format defines the format of the target value.
	// The default format is PEM.
	//+optional
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
type TargetMetadata struct {
	// Annotations is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('trust-manager.io/'))", reason=FieldValueForbidden, message="must not use forbidden domains as prefixes (e.g., trust-manager.io)"
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels is a key value map to be copied to the target.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self.all(k, !k.startsWith('trust-manager.io/'))", reason=FieldValueForbidden, message="must not use forbidden domains as prefixes (e.g., trust-manager.io)"
	Labels map[string]string `json:"labels,omitempty"`
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
	// DefaultPKCS12Password is the empty string, that will create a password-less PKCS12 truststore.
	// Password-less PKCS is the new default Java truststore from Java 18.
	// By password-less, it means the certificates are not encrypted, and it contains no MacData for integrity check.
	DefaultPKCS12Password = ""

	// BundleConditionSynced indicates that the Bundle has successfully synced
	// all source bundle data to the Bundle target in all Namespaces.
	BundleConditionSynced string = "Synced"

	BundleMigratedAnnotation string = "trust-manager.io/migrated"
)
