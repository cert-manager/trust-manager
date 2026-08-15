/*
Copyright 2026 The cert-manager Authors.

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

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"

	"hegel.dev/go/hegel"
)

var (
	conditionTypes    = []string{"A", "B", trustapi.BundleConditionSynced}
	conditionStatuses = []metav1.ConditionStatus{metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown}
)

// drawConditions draws a list of conditions with unique types, as enforced
// on the real API by the conditions field's listType=map / listMapKey=type
// markers. Each condition gets a distinct past LastTransitionTime so that
// time-preservation is observable.
func drawConditions(ht *hegel.T, base time.Time) []metav1.Condition {
	var conds []metav1.Condition
	for i, typ := range conditionTypes {
		if !hegel.Draw(ht, hegel.Booleans()) {
			continue
		}
		conds = append(conds, metav1.Condition{
			Type:               typ,
			Status:             hegel.Draw(ht, hegel.SampledFrom(conditionStatuses)),
			Reason:             hegel.Draw(ht, hegel.SampledFrom([]string{"ReasonA", "ReasonB"})),
			Message:            hegel.Draw(ht, hegel.SampledFrom([]string{"message a", "message b"})),
			ObservedGeneration: int64(hegel.Draw(ht, hegel.Integers(1, 3))),
			LastTransitionTime: metav1.Time{Time: base.Add(-time.Duration(i+1) * time.Hour)},
		})
	}
	return conds
}

// TestSetBundleConditionProperties: for any existing and patch conditions and
// any new condition, setBundleCondition must
//
//   - keep the LastTransitionTime of an existing condition with the same type
//     and status, and stamp "now" otherwise
//   - overwrite the patch entry of the same type in place, or append when
//     there is none, leaving all other entries untouched
//   - leave the patch list in a state where bundleHasCondition finds the new
//     condition
func TestSetBundleConditionProperties(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	hegel.Test(t, func(ht *hegel.T) {
		existing := drawConditions(ht, fixedTime)
		patch := drawConditions(ht, fixedTime)
		newCondition := metav1.Condition{
			Type:               hegel.Draw(ht, hegel.SampledFrom(conditionTypes)),
			Status:             hegel.Draw(ht, hegel.SampledFrom(conditionStatuses)),
			Reason:             hegel.Draw(ht, hegel.SampledFrom([]string{"ReasonA", "ReasonB"})),
			Message:            hegel.Draw(ht, hegel.SampledFrom([]string{"message a", "message b"})),
			ObservedGeneration: int64(hegel.Draw(ht, hegel.Integers(1, 3))),
		}

		patchBefore := append([]metav1.Condition(nil), patch...)
		b := &bundle{clock: fakeclock.NewFakeClock(fixedTime)}
		returned := b.setBundleCondition(existing, &patch, newCondition)

		wantTime := metav1.Time{Time: fixedTime}
		for _, cond := range existing {
			if cond.Type == newCondition.Type && cond.Status == newCondition.Status {
				wantTime = cond.LastTransitionTime
			}
		}
		wantCondition := newCondition
		wantCondition.LastTransitionTime = wantTime

		if !apiequality.Semantic.DeepEqual(returned, wantCondition) {
			ht.Fatalf("returned condition = %#v, want %#v", returned, wantCondition)
		}

		wantPatch := append([]metav1.Condition(nil), patchBefore...)
		replaced := false
		for i, cond := range wantPatch {
			if cond.Type == newCondition.Type {
				wantPatch[i] = wantCondition
				replaced = true
			}
		}
		if !replaced {
			wantPatch = append(wantPatch, wantCondition)
		}
		if !apiequality.Semantic.DeepEqual(patch, wantPatch) {
			ht.Fatalf("patch conditions = %#v, want %#v", patch, wantPatch)
		}

		if !bundleHasCondition(patch, newCondition) {
			ht.Fatalf("bundleHasCondition does not find the condition just set")
		}
	}, hegel.WithTestCases(1000))
}

// TestBundleHasConditionProperty: bundleHasCondition is true iff the list
// contains a condition matching the search condition on type, status, reason,
// message and observed generation, with LastTransitionTime ignored.
func TestBundleHasConditionProperty(t *testing.T) {
	fixedTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	hegel.Test(t, func(ht *hegel.T) {
		existing := drawConditions(ht, fixedTime)
		search := metav1.Condition{
			Type:               hegel.Draw(ht, hegel.SampledFrom(conditionTypes)),
			Status:             hegel.Draw(ht, hegel.SampledFrom(conditionStatuses)),
			Reason:             hegel.Draw(ht, hegel.SampledFrom([]string{"ReasonA", "ReasonB"})),
			Message:            hegel.Draw(ht, hegel.SampledFrom([]string{"message a", "message b"})),
			ObservedGeneration: int64(hegel.Draw(ht, hegel.Integers(1, 3))),
			// Deliberately different from any existing LastTransitionTime.
			LastTransitionTime: metav1.Time{Time: fixedTime.Add(time.Hour)},
		}

		want := false
		for _, cond := range existing {
			if cond.Type == search.Type &&
				cond.Status == search.Status &&
				cond.Reason == search.Reason &&
				cond.Message == search.Message &&
				cond.ObservedGeneration == search.ObservedGeneration {
				want = true
			}
		}
		if got := bundleHasCondition(existing, search); got != want {
			ht.Fatalf("bundleHasCondition = %v, want %v (existing=%#v, search=%#v)", got, want, existing, search)
		}
	}, hegel.WithTestCases(1000))
}

// TestSetBundleStatusDefaultCAVersionProperties: after the call, the status
// version always equals requiredID, and the return value reports whether
// that changed anything.
func TestSetBundleStatusDefaultCAVersionProperties(t *testing.T) {
	versions := []string{"", "123", "456"}

	hegel.Test(t, func(ht *hegel.T) {
		current := hegel.Draw(ht, hegel.SampledFrom(versions))
		requiredID := hegel.Draw(ht, hegel.SampledFrom(versions))

		status := trustapi.BundleStatus{DefaultCAPackageVersion: current}
		b := &bundle{}
		changed := b.setBundleStatusDefaultCAVersion(&status, requiredID)

		if status.DefaultCAPackageVersion != requiredID {
			ht.Fatalf("status version = %q, want %q", status.DefaultCAPackageVersion, requiredID)
		}
		if changed != (current != requiredID) {
			ht.Fatalf("changed = %v, want %v (current=%q, requiredID=%q)", changed, current != requiredID, current, requiredID)
		}
	}, hegel.WithTestCases(200))
}
