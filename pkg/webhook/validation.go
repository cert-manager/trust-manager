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
	"strconv"
	"sync"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

// validator validates against trust.cert-manager.io resources.
type validator struct {
	log logr.Logger

	lock sync.RWMutex
}

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
	log := v.log.WithValues("name", bundle.Name)
	log.V(2).Info("received validation request")
	var (
		el       field.ErrorList
		warnings admission.Warnings
		path     = field.NewPath("spec")
	)

	sourceCount := 0
	defaultCAsCount := 0

	for i, source := range bundle.Spec.Sources {
		path := path.Child("sources").Child("[" + strconv.Itoa(i) + "]")

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
			if len(configMap.Key) == 0 {
				el = append(el, field.Invalid(path.Child("key"), configMap.Key, "source configMap key must be defined"))
			}
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
			if len(secret.Key) == 0 {
				el = append(el, field.Invalid(path.Child("key"), secret.Key, "source secret key must be defined"))
			}
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

	configMap := bundle.Spec.Target.ConfigMap
	secret := bundle.Spec.Target.Secret

	if configMap == nil && secret == nil {
		el = append(el, field.Invalid(path.Child("target"), bundle.Spec.Target, "must define at least one target"))
	}

	if configMap != nil && len(configMap.Key) == 0 {
		el = append(el, field.Invalid(path.Child("target", "configMap", "key"), configMap.Key, "target configMap key must be defined"))
	}

	if secret != nil && len(secret.Key) == 0 {
		el = append(el, field.Invalid(path.Child("target", "secret", "key"), secret.Key, "target secret key must be defined"))
	}

	if bundle.Spec.Target.AdditionalFormats != nil {
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
					el = append(el, field.Invalid(path.Child("target", "additionalFormats", f, "key"), selector.Key, "key must be unique in target configMap"))
				}
				targetKeys[selector.Key] = struct{}{}
			}
		}
	}

	if nsSel := bundle.Spec.Target.NamespaceSelector; nsSel != nil && len(nsSel.MatchLabels) > 0 {
		if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSel.MatchLabels}); err != nil {
			el = append(el, field.Invalid(path.Child("target", "namespaceSelector", "matchLabels"), nsSel.MatchLabels, err.Error()))
		}
	}

	return warnings, el.ToAggregate()

}
