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

package webhook

import (
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// Options are options for running the wehook.
type Options struct {
	Log logr.Logger
}

// Register the webhook endpoints against the Manager.
func Register(mgr manager.Manager, opts Options) error {
	opts.Log.Info("registering webhook endpoints")
	validator := &validator{log: opts.Log.WithName("validation")}
	err := builder.WebhookManagedBy(mgr).
		For(&trustapi.Bundle{}).
		WithValidator(validator).
		Complete()
	if err != nil {
		return fmt.Errorf("error registering webhook: %v", err)
	}
	mgr.AddReadyzCheck("validator", mgr.GetWebhookServer().StartedChecker())
	return nil
}
