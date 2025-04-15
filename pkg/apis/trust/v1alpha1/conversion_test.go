/*
Copyright 2025 The cert-manager Authors.

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
	"testing"

	trustv1alpha2 "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	utilconversion "github.com/cert-manager/trust-manager/pkg/util/conversion"
)

func TestFuzzyConversion(t *testing.T) {
	t.Run("for Bundle", utilconversion.FuzzTestFunc(utilconversion.FuzzTestFuncInput{
		Hub:   &trustv1alpha2.ClusterBundle{},
		Spoke: &Bundle{},
	}))
}
