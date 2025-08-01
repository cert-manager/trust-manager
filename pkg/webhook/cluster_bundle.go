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
	"context"
	"fmt"

	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
)

func (webhook *ClusterBundle) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(&trustmanagerapi.ClusterBundle{}).
		WithValidator(webhook).
		Complete()
}

// ClusterBundle validates ClusterBundle against rules that are currently not
// available in Kubernetes OpenAPI schema nor CEL.
type ClusterBundle struct{}

var _ admission.CustomValidator = &ClusterBundle{}

func (webhook *ClusterBundle) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return webhook.validate(ctx, obj)
}

func (webhook *ClusterBundle) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	return webhook.validate(ctx, newObj)
}

func (webhook *ClusterBundle) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	// always allow deletes
	return nil, nil
}

func (webhook *ClusterBundle) validate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	bundle, ok := obj.(*trustmanagerapi.ClusterBundle)
	if !ok {
		return nil, fmt.Errorf("expected a ClusterBundle, but got a %T", obj)
	}
	log := logf.FromContext(ctx, "name", bundle.Name)
	log.V(2).Info("received validation request")
	var (
		el       field.ErrorList
		warnings admission.Warnings
		fldPath  = field.NewPath("spec")
	)

	for i, source := range bundle.Spec.Sources {
		el = append(el, webhook.validateSource(source, fldPath.Child("sources").Index(i))...)
	}

	el = append(el, webhook.validateTarget(bundle.Spec.Target, fldPath.Child("target"))...)

	return warnings, el.ToAggregate()

}

func (webhook *ClusterBundle) validateSource(source trustmanagerapi.BundleSource, fldPath *field.Path) field.ErrorList {
	return validation.ValidateLabelSelector(source.Selector, validation.LabelSelectorValidationOptions{}, fldPath.Child("selector"))
}

func (webhook *ClusterBundle) validateTarget(target trustmanagerapi.BundleTarget, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList

	if target.ConfigMap != nil {
		el = append(el, webhook.validateTargetMetadata(target.ConfigMap.Metadata, fldPath.Child("configMap", "metadata"))...)
	}
	if target.Secret != nil {
		el = append(el, webhook.validateTargetMetadata(target.Secret.Metadata, fldPath.Child("secret", "metadata"))...)
	}
	el = append(el, validation.ValidateLabelSelector(target.NamespaceSelector, validation.LabelSelectorValidationOptions{}, fldPath.Child("namespaceSelector"))...)

	return el
}

// validateTargetMetadata validates that the target template annotations and labels are both valid and that they do not contain reserved keys.
func (webhook *ClusterBundle) validateTargetMetadata(targetMetadata *trustmanagerapi.TargetMetadata, fldPath *field.Path) field.ErrorList {
	if targetMetadata == nil {
		return nil
	}

	var el field.ErrorList

	el = append(el, apivalidation.ValidateAnnotations(targetMetadata.Annotations, fldPath.Child("annotations"))...)
	el = append(el, validation.ValidateLabels(targetMetadata.Labels, fldPath.Child("labels"))...)

	return el
}
