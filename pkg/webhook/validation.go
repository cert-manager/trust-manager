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
	"strings"

	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// validator validates against trust.cert-manager.io resources.
type validator struct{}

var _ admission.CustomValidator = &validator{}

func (v *validator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return v.validate(ctx, obj)
}

func (v *validator) ValidateUpdate(ctx context.Context, _, newObj runtime.Object) (admission.Warnings, error) {
	return v.validate(ctx, newObj)
}

func (v *validator) ValidateDelete(_ context.Context, _ runtime.Object) (admission.Warnings, error) {
	// always allow deletes
	return nil, nil
}

func (v *validator) validate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	bundle, ok := obj.(*trustapi.Bundle)
	if !ok {
		return nil, fmt.Errorf("expected a Bundle, but got a %T", obj)
	}
	log := logf.FromContext(ctx, "name", bundle.Name)
	log.V(2).Info("received validation request")
	var (
		el       field.ErrorList
		warnings admission.Warnings
		path     = field.NewPath("spec")
	)

	for i, source := range bundle.Spec.Sources {
		path := path.Child("sources").Index(i)

		if configMap := source.ConfigMap; configMap != nil {
			path := path.Child("configMap")

			errs := validation.ValidateLabelSelector(configMap.Selector, validation.LabelSelectorValidationOptions{}, path.Child("selector"))
			el = append(el, errs...)
		}

		if secret := source.Secret; secret != nil {
			path := path.Child("secret")

			errs := validation.ValidateLabelSelector(secret.Selector, validation.LabelSelectorValidationOptions{}, path.Child("selector"))
			el = append(el, errs...)
		}
	}

	if target := bundle.Spec.Target.ConfigMap; target != nil {
		path := path.Child("sources")
		for i, source := range bundle.Spec.Sources {
			if source.ConfigMap != nil && source.ConfigMap.Name == bundle.Name && source.ConfigMap.Key == target.Key {
				el = append(el, field.Forbidden(path.Child(fmt.Sprintf("[%d]", i), "configMap", source.ConfigMap.Name, source.ConfigMap.Key), "cannot define the same source as target"))
			}
		}
	}

	if target := bundle.Spec.Target.Secret; target != nil {
		path := path.Child("sources")
		for i, source := range bundle.Spec.Sources {
			if source.Secret != nil && source.Secret.Name == bundle.Name && source.Secret.Key == target.Key {
				el = append(el, field.Forbidden(path.Child(fmt.Sprintf("[%d]", i), "secret", source.Secret.Name, source.Secret.Key), "cannot define the same source as target"))
			}
		}
	}

	if bundle.Spec.Target.ConfigMap != nil {
		el = append(el, validateTargetMetadata(bundle.Spec.Target.ConfigMap.Metadata, path.Child("target", "configMap", "metadata"))...)
	}
	if bundle.Spec.Target.Secret != nil {
		el = append(el, validateTargetMetadata(bundle.Spec.Target.Secret.Metadata, path.Child("target", "secret", "metadata"))...)
	}

	errs := validation.ValidateLabelSelector(bundle.Spec.Target.NamespaceSelector, validation.LabelSelectorValidationOptions{}, path.Child("target", "namespaceSelector"))
	el = append(el, errs...)

	return warnings, el.ToAggregate()

}

// validateAnnotationsLabelsTemplate Validates that the target template annotations and labels are both valid and that they do not contain reserved keys.
func validateTargetMetadata(targetMetadata *trustapi.TargetMetadata, fldPath *field.Path) field.ErrorList {
	if targetMetadata == nil {
		return nil
	}

	el := field.ErrorList{}

	templateAnnotationsPath := fldPath.Child("annotations")
	for key := range targetMetadata.Annotations {
		if strings.HasPrefix(key, "trust.cert-manager.io/") {
			el = append(el, field.Invalid(templateAnnotationsPath, key, "trust.cert-manager.io/* annotations are not allowed"))
		}
		if strings.HasPrefix(key, "trust-manager.io/") {
			el = append(el, field.Invalid(templateAnnotationsPath, key, "trust-manager.io/* annotations are not allowed"))
		}
	}
	el = append(el, apivalidation.ValidateAnnotations(targetMetadata.Annotations, templateAnnotationsPath)...)

	templateLabelsPath := fldPath.Child("labels")
	for key := range targetMetadata.Labels {
		if strings.HasPrefix(key, "trust.cert-manager.io/") {
			el = append(el, field.Invalid(templateLabelsPath, key, "trust.cert-manager.io/* labels are not allowed"))
		}
		if strings.HasPrefix(key, "trust-manager.io/") {
			el = append(el, field.Invalid(templateLabelsPath, key, "trust-manager.io/* labels are not allowed"))
		}
	}
	el = append(el, validation.ValidateLabels(targetMetadata.Labels, templateLabelsPath)...)

	return el
}
