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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Target",type="string",JSONPath=".spec.target.configMap.key",description="Bundle Target Key"
// +kubebuilder:printcolumn:name="Synced",type="string",JSONPath=".status.condition.status",description="Bundle has been synced"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.condition.reason",description="Reason Bundle has Synced status"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

type Bundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// TODO
	Spec BundleSpec `json:"spec"`

	// TODO
	// +optional
	Status BundleStatus `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type BundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Bundle `json:"items"`
}

// TODO
type BundleSpec struct {
	// TODO
	Sources []BundleSource `json:"sources"`

	// TODO
	Target BundleTarget `json:"target"`
}

// TODO
type BundleSource struct {
	// +optional
	ConfigMap *ObjectKeySelector `json:"configMap,omitempty"`

	// +optional
	Secret *ObjectKeySelector `json:"secret,omitempty"`

	// +optional
	InLine *string `json:"inLine,omitempty"`
}

// TODO
type BundleTarget struct {
	// TODO
	ConfigMap *LocalKeySelector `json:"configMap"`
}

// TODO
type ObjectKeySelector struct {
	// The name of the Secret resource being referred to.
	// TODO
	Name string `json:"name"`

	// The key of the entry in the Secret resource's `data` field to be used.
	// TODO
	LocalKeySelector `json:",inline"`
}

// TODO
type LocalKeySelector struct {
	// The key of the entry in the Secret resource's `data` field to be used.
	// TODO
	Key string `json:"key,omitempty"`
}

type BundleStatus struct {
	Target *BundleTarget `json:"target"`

	// +optional
	Condition BundleCondition `json:"condition,omitempty"`
}

// TODO
type BundleCondition struct {
	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Bundle.
	// TODO
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}
