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

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// setBundleCondition updates the bundle with the given condition.
// Will overwrite any existing condition of the same type.
// LastTransitionTime will not be updated if an existing condition of the same
// Type and Status already exists.
func (b *bundle) setBundleCondition(
	existingConditions []trustapi.BundleCondition,
	patchConditions *[]trustapi.BundleCondition,
	newCondition trustapi.BundleCondition,
) trustapi.BundleCondition {
	newCondition.LastTransitionTime = &metav1.Time{Time: b.clock.Now()}

	// Reset the LastTransitionTime if the status hasn't changed
	for _, cond := range existingConditions {
		if cond.Type != newCondition.Type {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == newCondition.Status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		}
	}

	// Search through existing conditions
	for idx, cond := range *patchConditions {
		// Skip unrelated conditions
		if cond.Type != newCondition.Type {
			continue
		}

		// Overwrite the existing condition
		(*patchConditions)[idx] = newCondition

		return newCondition
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	*patchConditions = append(*patchConditions, newCondition)

	return newCondition
}
