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
	"fmt"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// bundleHasCondition returns true if the bundle has an exact matching condition.
// The given condition will have the ObservedGeneration set to the bundle Generation.
// The LastTransitionTime is ignored.
func bundleHasCondition(
	existingConditions []metav1.Condition,
	searchCondition metav1.Condition,
) bool {
	existingCondition := meta.FindStatusCondition(existingConditions, searchCondition.Type)
	if existingCondition == nil {
		return false
	}
	// Compare all fields except LastTransitionTime
	// We ignore the LastTransitionTime as this is set by the controller
	return existingCondition.Status == searchCondition.Status &&
		existingCondition.Reason == searchCondition.Reason &&
		existingCondition.Message == searchCondition.Message &&
		existingCondition.ObservedGeneration == searchCondition.ObservedGeneration
}

// setBundleCondition updates the bundle with the given condition.
// Will overwrite any existing condition of the same type.
// LastTransitionTime will not be updated if an existing condition of the same
// Type and Status already exists.
func (b *bundle) setBundleCondition(
	existingConditions []metav1.Condition,
	patchConditions *[]metav1.Condition,
	newCondition metav1.Condition,
) metav1.Condition {
	if cond := meta.FindStatusCondition(*patchConditions, newCondition.Type); cond != nil {
		panic(fmt.Sprintf("condition %q already added to patch conditions; this is probably a bug", newCondition.Type))
	}

	existingCondition := meta.FindStatusCondition(existingConditions, newCondition.Type)
	// If this update doesn't contain a state transition, we don't update
	// the conditions LastTransitionTime to Now()
	if existingCondition != nil && existingCondition.Status == newCondition.Status {
		newCondition.LastTransitionTime = existingCondition.LastTransitionTime
	} else {
		if newCondition.LastTransitionTime.IsZero() {
			newCondition.LastTransitionTime = metav1.Time{Time: b.clock.Now()}
		}
	}

	*patchConditions = append(*patchConditions, newCondition)
	return newCondition
}

// setBundleStatusDefaultCAVersion ensures that the given Bundle's Status correctly
// reflects the defaultCAVersion represented by requiredID.
// Returns true if the bundle status needs updating.
func (b *bundle) setBundleStatusDefaultCAVersion(
	bundleStatus *trustapi.BundleStatus,
	requiredID string,
) bool {
	currentVersion := bundleStatus.DefaultCAPackageVersion

	// If both are empty, we don't need to update
	if len(requiredID) == 0 && currentVersion == nil {
		return false
	}

	// If requiredID is empty, we need to update if currentVersion is not
	if len(requiredID) == 0 && currentVersion != nil {
		bundleStatus.DefaultCAPackageVersion = nil
		return true
	}

	// If requiredID is not empty, we need to update if currentVersion is empty or
	// if currentVersion is not equal to requiredID
	if currentVersion == nil || *currentVersion != requiredID {
		bundleStatus.DefaultCAPackageVersion = &requiredID
		return true
	}

	return false
}
