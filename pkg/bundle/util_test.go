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

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeclock "k8s.io/utils/clock/testing"
)

func Test_setBundleCondition(t *testing.T) {
	const bundleGeneration int64 = 2
	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
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
				{Type: "B"},
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
				{Type: "B"},
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
				{Type: "B"},
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
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: &metav1.Time{Time: fixedTime.Add(-time.Second)},
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
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: &metav1.Time{Time: fixedTime.Add(-time.Second)},
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

			b.setBundleCondition(
				bundle.Status.Conditions,
				&bundle.Status.Conditions,
				trustapi.BundleCondition{
					Type:               test.newCondition.Type,
					Status:             test.newCondition.Status,
					Reason:             test.newCondition.Reason,
					Message:            test.newCondition.Message,
					ObservedGeneration: bundle.Generation,
				},
			)

			if !apiequality.Semantic.DeepEqual(bundle.Status.Conditions, test.expectedConditions) {
				t.Errorf("unexpected resulting conditions, exp=%v got=%v", test.expectedConditions, bundle.Status.Conditions)
			}
		})
	}
}
