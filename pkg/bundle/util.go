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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
)

// TODO
func (b *bundle) setBundleCondition(bundle *trustapi.Bundle, condition trustapi.BundleCondition) {
	condition.LastTransitionTime = &metav1.Time{b.clock.Now()}
	condition.ObservedGeneration = bundle.Generation

	var existingConditions []trustapi.BundleCondition
	for _, existingCondition := range bundle.Status.Conditions {

		// Append existing conditions which do not match the type
		if existingCondition.Type != condition.Type {
			existingConditions = append(existingConditions, existingCondition)
			continue
		}

		// If the status is the same, don't modify the last transaction time
		if existingCondition.Status == condition.Status {
			condition.LastTransitionTime = existingCondition.LastTransitionTime
		}
	}

	// Set the bundle conditions
	bundle.Status.Conditions = existingConditions
}
