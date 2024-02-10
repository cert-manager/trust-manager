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
	"testing"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

func Test_bundleHasCondition(t *testing.T) {
	const bundleGeneration int64 = 2
	var (
		fixedTime = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
	)

	tests := map[string]struct {
		existingConditions []trustapi.BundleCondition
		newCondition       trustapi.BundleCondition
		expectHasCondition bool
	}{
		"no existing conditions returns no matching condition": {
			existingConditions: []trustapi.BundleCondition{},
			newCondition:       trustapi.BundleCondition{Reason: "A", ObservedGeneration: bundleGeneration},
			expectHasCondition: false,
		},
		"an existing condition which doesn't match the current condition should return false": {
			existingConditions: []trustapi.BundleCondition{{Reason: "B"}},
			newCondition:       trustapi.BundleCondition{Reason: "A", ObservedGeneration: bundleGeneration},
			expectHasCondition: false,
		},
		"an existing condition which shares the same condition but is an older generation should return false": {
			existingConditions: []trustapi.BundleCondition{{Reason: "A", ObservedGeneration: bundleGeneration - 1}},
			newCondition:       trustapi.BundleCondition{Reason: "A", ObservedGeneration: bundleGeneration},
			expectHasCondition: false,
		},
		"an existing condition which shares the same condition and generation should return true": {
			existingConditions: []trustapi.BundleCondition{{Reason: "A", ObservedGeneration: bundleGeneration}},
			newCondition:       trustapi.BundleCondition{Reason: "A", ObservedGeneration: bundleGeneration},
			expectHasCondition: true,
		},
		"an existing condition with a different LastTransitionTime should return true still": {
			existingConditions: []trustapi.BundleCondition{{Reason: "A", ObservedGeneration: bundleGeneration, LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)}}},
			newCondition:       trustapi.BundleCondition{Reason: "A", ObservedGeneration: bundleGeneration},
			expectHasCondition: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			hasCondition := bundleHasCondition(test.existingConditions, test.newCondition)
			if hasCondition != test.expectHasCondition {
				t.Errorf("unexpected has condition, exp=%t got=%t", test.expectHasCondition, hasCondition)
			}
		})
	}
}

func Test_setBundleCondition(t *testing.T) {
	const bundleGeneration int64 = 2
	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingConditions []trustapi.BundleCondition
		newCondition       trustapi.BundleCondition
		expectedConditions []trustapi.BundleCondition
	}{
		"no existing conditions should add the condition with time and gen to the bundle": {
			existingConditions: []trustapi.BundleCondition{},
			newCondition: trustapi.BundleCondition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: bundleGeneration,
				},
			},
		},
		"an existing condition of different type should add a different condition with time and gen to the bundle": {
			existingConditions: []trustapi.BundleCondition{{Type: "B"}},
			newCondition: trustapi.BundleCondition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: bundleGeneration,
				},
			},
		},
		"an existing condition of the same type but different status should be replaced with new time if it has a different status": {
			existingConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionFalse,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: bundleGeneration - 1,
				},
			},
			newCondition: trustapi.BundleCondition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: bundleGeneration,
				},
			},
		},
		"an existing condition of the same type and status should be replaced with same time": {
			existingConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: bundleGeneration - 1,
				},
			},
			newCondition: trustapi.BundleCondition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []trustapi.BundleCondition{
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: bundleGeneration,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b := &bundle{clock: fixedclock}
			bundle := &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Generation: bundleGeneration,
				},
				Status: trustapi.BundleStatus{
					Conditions: test.existingConditions,
				},
			}

			var patchConditions []trustapi.BundleCondition
			b.setBundleCondition(
				bundle.Status.Conditions,
				&patchConditions,
				trustapi.BundleCondition{
					Type:               test.newCondition.Type,
					Status:             test.newCondition.Status,
					Reason:             test.newCondition.Reason,
					Message:            test.newCondition.Message,
					ObservedGeneration: bundle.Generation,
				},
			)

			if !apiequality.Semantic.DeepEqual(patchConditions, test.expectedConditions) {
				t.Errorf("unexpected resulting conditions, exp=%v got=%v", test.expectedConditions, bundle.Status.Conditions)
			}
		})
	}
}

func Test_setBundleStatusDefaultCAVersion(t *testing.T) {
	var (
		fixedTime  = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedclock = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		inputBundle                     trustapi.Bundle
		requiredID                      string
		expectedDefaultCAPackageVersion *string
		expectUpdate                    bool
	}{
		"requiredID empty but status populated; should update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: ptr.To("abc123"),
				},
			},
			requiredID:                      "",
			expectedDefaultCAPackageVersion: nil,
			expectUpdate:                    true,
		},
		"requiredID empty but status populated but empty; should update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: ptr.To(""),
				},
			},
			requiredID:                      "",
			expectedDefaultCAPackageVersion: nil,
			expectUpdate:                    true,
		},
		"requiredID empty and status nil; should not update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: nil,
				},
			},
			requiredID:                      "",
			expectedDefaultCAPackageVersion: nil,
			expectUpdate:                    false,
		},
		"requiredID not empty and status nil; should update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: nil,
				},
			},
			requiredID:                      "abc123",
			expectedDefaultCAPackageVersion: ptr.To("abc123"),
			expectUpdate:                    true,
		},
		"requiredID not empty and status populated but incorrect; should update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: ptr.To("def456"),
				},
			},
			requiredID:                      "abc123",
			expectedDefaultCAPackageVersion: ptr.To("abc123"),
			expectUpdate:                    true,
		},
		"requiredID not empty and status populated currectly; should not update": {
			inputBundle: trustapi.Bundle{
				Status: trustapi.BundleStatus{
					DefaultCAPackageVersion: ptr.To("abc123"),
				},
			},
			requiredID:                      "abc123",
			expectedDefaultCAPackageVersion: ptr.To("abc123"),
			expectUpdate:                    false,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			b := &bundle{clock: fixedclock}

			shouldUpdate := b.setBundleStatusDefaultCAVersion(&test.inputBundle.Status, test.requiredID)

			if shouldUpdate != test.expectUpdate {
				t.Errorf("expected shouldUpdate=%v got=%v", test.expectUpdate, shouldUpdate)
			}

			finalVersion := test.inputBundle.Status.DefaultCAPackageVersion

			if !apiequality.Semantic.DeepEqual(finalVersion, test.expectedDefaultCAPackageVersion) {
				t.Errorf("expected DefaultCAPackageVersion=%v, got=%v", test.expectedDefaultCAPackageVersion, finalVersion)
			}
		})
	}
}
