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

//nolint:staticcheck // SA1019 staticcheck will warn about our use of the deprecated Bundle resource, but we still need to validate it to people can migrate
package webhook

import (
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// SetupWebhookWithManager the webhook endpoints against the Manager.
func SetupWebhookWithManager(mgr manager.Manager) error {
	return builder.WebhookManagedBy(mgr, &trustapi.Bundle{}).
		WithValidator(&validator{}).
		Complete()
}
