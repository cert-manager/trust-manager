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
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// validator validates against trust.cert-manager.io resources.
type validator struct{}

var _ admission.Validator[*trustapi.Bundle] = &validator{}

func (v *validator) ValidateCreate(ctx context.Context, obj *trustapi.Bundle) (admission.Warnings, error) {
	return v.validate(ctx, obj)
}

func (v *validator) ValidateUpdate(ctx context.Context, _, newObj *trustapi.Bundle) (admission.Warnings, error) {
	return v.validate(ctx, newObj)
}

func (v *validator) ValidateDelete(_ context.Context, _ *trustapi.Bundle) (admission.Warnings, error) {
	// always allow deletes
	return nil, nil
}

func (v *validator) validate(ctx context.Context, bundle *trustapi.Bundle) (admission.Warnings, error) {
	log := logf.FromContext(ctx, "name", bundle.Name)
	log.V(2).Info("received validation request")
	var (
		el       field.ErrorList
		warnings admission.Warnings
		path     = field.NewPath("spec")
	)

	sourceCount := 0
	defaultCAsCount := 0

	for i, source := range bundle.Spec.Sources {
		path := path.Child("sources").Index(i)

		unionCount := 0

		if configMap := source.ConfigMap; configMap != nil {
			path := path.Child("configMap")
			sourceCount++
			unionCount++

			if len(configMap.Name) == 0 && configMap.Selector == nil {
				el = append(el, field.Invalid(path, "name: ' ', selector: nil", "must validate one and only one schema (oneOf): [name, selector]. Found none valid"))
			}
			if len(configMap.Name) > 0 && configMap.Selector != nil {
				el = append(el, field.Invalid(path, fmt.Sprintf("name: %s, selector: {}", configMap.Name), "must validate one and only one schema (oneOf): [name, selector]. Found both set"))
			}
			if includeAllKeys := ptr.Deref(configMap.IncludeAllKeys, false); len(configMap.Key) == 0 && !includeAllKeys {
				el = append(el, field.Invalid(path, fmt.Sprintf("key: ' ', includeAllKeys: %t", includeAllKeys), "source configMap key must be defined when includeAllKeys is false"))
			}
			if includeAllKeys := ptr.Deref(configMap.IncludeAllKeys, false); len(configMap.Key) > 0 && includeAllKeys {
				el = append(el, field.Invalid(path, fmt.Sprintf("key: %s, includeAllKeys: %t", configMap.Key, includeAllKeys), "source configMap key cannot be defined when includeAllKeys is true"))
			}

			errs := validation.ValidateLabelSelector(configMap.Selector, validation.LabelSelectorValidationOptions{}, path.Child("selector"))
			el = append(el, errs...)
		}

		if secret := source.Secret; secret != nil {
			path := path.Child("secret")
			sourceCount++
			unionCount++

			if len(secret.Name) == 0 && secret.Selector == nil {
				el = append(el, field.Invalid(path, "name: ' ', selector: nil", "must validate one and only one schema (oneOf): [name, selector]. Found none valid"))
			}
			if len(secret.Name) > 0 && secret.Selector != nil {
				el = append(el, field.Invalid(path, fmt.Sprintf("name: %s, selector: {}", secret.Name), "must validate one and only one schema (oneOf): [name, selector]. Found both set"))
			}
			if includeAllKeys := ptr.Deref(secret.IncludeAllKeys, false); len(secret.Key) == 0 && !includeAllKeys {
				el = append(el, field.Invalid(path, fmt.Sprintf("key: ' ', includeAllKeys: %t", includeAllKeys), "source secret key must be defined when includeAllKeys is false"))
			}
			if includeAllKeys := ptr.Deref(secret.IncludeAllKeys, false); len(secret.Key) > 0 && includeAllKeys {
				el = append(el, field.Invalid(path, fmt.Sprintf("key: %s, includeAllKeys: %t", secret.Key, includeAllKeys), "source secret key cannot be defined when includeAllKeys is true"))
			}

			errs := validation.ValidateLabelSelector(secret.Selector, validation.LabelSelectorValidationOptions{}, path.Child("selector"))
			el = append(el, errs...)
		}

		if source.InLine != nil {
			sourceCount++
			unionCount++
		}

		if source.UseDefaultCAs != nil {
			defaultCAsCount++
			unionCount++

			if *source.UseDefaultCAs {
				sourceCount++
			}
		}

		if unionCount != 1 {
			el = append(el, field.Forbidden(
				path, fmt.Sprintf("must define exactly one source type for each item but found %d defined types", unionCount),
			))
		}
	}

	if sourceCount == 0 {
		el = append(el, field.Forbidden(path.Child("sources"), "must define at least one source"))
	}

	if defaultCAsCount > 1 {
		el = append(el, field.Forbidden(
			path.Child("sources"),
			fmt.Sprintf("must request default CAs either once or not at all but got %d requests", defaultCAsCount),
		))
	}

	if target := bundle.Spec.Target.ConfigMap; target != nil {
		path := path.Child("sources")
		for i, source := range bundle.Spec.Sources {
			if source.ConfigMap != nil && source.ConfigMap.Name == bundle.Name && source.ConfigMap.Key == target.Key {
				el = append(el, field.Forbidden(
					path.Index(i).Child("configMap", source.ConfigMap.Name, source.ConfigMap.Key),
					"cannot define the same source as target",
				))
			}
		}
	}

	if target := bundle.Spec.Target.Secret; target != nil {
		path := path.Child("sources")
		for i, source := range bundle.Spec.Sources {
			if source.Secret != nil && source.Secret.Name == bundle.Name && source.Secret.Key == target.Key {
				el = append(el, field.Forbidden(
					path.Index(i).Child("secret", source.Secret.Name, source.Secret.Key),
					"cannot define the same source as target",
				))
			}
		}
	}

	if bundle.Spec.Target.AdditionalFormats != nil {
		configMap := bundle.Spec.Target.ConfigMap
		secret := bundle.Spec.Target.Secret

		var formats = make(map[string]*trustapi.KeySelector)
		targetKeys := map[string]struct{}{}
		if configMap != nil {
			targetKeys[configMap.Key] = struct{}{}
		}
		if secret != nil {
			targetKeys[secret.Key] = struct{}{}
		}

		// Checks for nil to avoid nil point dereference error
		if bundle.Spec.Target.AdditionalFormats.JKS != nil {
			formats["jks"] = &bundle.Spec.Target.AdditionalFormats.JKS.KeySelector
		}

		// Checks for nil to avoid nil point dereference error
		if bundle.Spec.Target.AdditionalFormats.PKCS12 != nil {
			formats["pkcs12"] = &bundle.Spec.Target.AdditionalFormats.PKCS12.KeySelector
		}

		for f, selector := range formats {
			if selector != nil {
				if _, ok := targetKeys[selector.Key]; ok {
					el = append(el, field.Invalid(
						path.Child("target", "additionalFormats", f, "key"), selector.Key,
						"key must be unique in target configMap",
					))
				}
				targetKeys[selector.Key] = struct{}{}
			}
		}
	}

	if bundle.Spec.Target.ConfigMap != nil {
		errs := validateTargetMetadata(bundle.Spec.Target.ConfigMap.Metadata, path.Child("target", "configMap", "metadata"))
		el = append(el, errs...)
	}
	if bundle.Spec.Target.Secret != nil {
		errs := validateTargetMetadata(bundle.Spec.Target.Secret.Metadata, path.Child("target", "secret", "metadata"))
		el = append(el, errs...)
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
