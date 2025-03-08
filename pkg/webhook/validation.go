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

func (v *validator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	oldBundle, ok := oldObj.(*trustapi.Bundle)
	if !ok {
		return nil, fmt.Errorf("expected a Bundle, but got a %T", oldBundle)
	}
	newBundle, ok := newObj.(*trustapi.Bundle)
	if !ok {
		return nil, fmt.Errorf("expected a Bundle, but got a %T", newBundle)
	}

	var (
		el   field.ErrorList
		path = field.NewPath("spec")
	)
	// Target removal are not allowed.
	if oldBundle.Spec.Target.ConfigMap != nil && newBundle.Spec.Target.ConfigMap == nil {
		el = append(el, field.Invalid(path.Child("target", "configmap"), "", "target configMap removal is not allowed"))
		return nil, el.ToAggregate()
	}
	// Target removal are not allowed.
	if oldBundle.Spec.Target.Secret != nil && newBundle.Spec.Target.Secret == nil {
		el = append(el, field.Invalid(path.Child("target", "secret"), "", "target secret removal is not allowed"))
		return nil, el.ToAggregate()
	}
	return v.validate(ctx, newObj)
}

func (v *validator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
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

	errs := validation.ValidateLabelSelector(bundle.Spec.Target.NamespaceSelector, validation.LabelSelectorValidationOptions{}, path.Child("target", "namespaceSelector"))
	el = append(el, errs...)

	return warnings, el.ToAggregate()

}
