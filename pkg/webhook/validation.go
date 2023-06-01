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
	if len(bundle.Spec.Sources) == 0 {
		el = append(el, field.Forbidden(path.Child("sources"), "must define at least one source"))
	} else {
		path := path.Child("sources")

		defaultCAsCount := 0

		for i, source := range bundle.Spec.Sources {
			path := path.Child("[" + strconv.Itoa(i) + "]")

			unionCount := 0

			if configMap := source.ConfigMap; configMap != nil {
				path := path.Child("configMap")
				unionCount++

				if len(configMap.Name) == 0 {
					el = append(el, field.Invalid(path.Child("name"), configMap.Name, "source configMap name must be defined"))
				}
				if len(configMap.Key) == 0 {
					el = append(el, field.Invalid(path.Child("key"), configMap.Key, "source configMap key must be defined"))
				}
			}

			if secret := source.Secret; secret != nil {
				path := path.Child("secret")
				unionCount++

				if len(secret.Name) == 0 {
					el = append(el, field.Invalid(path.Child("name"), secret.Name, "source secret name must be defined"))
				}
				if len(secret.Key) == 0 {
					el = append(el, field.Invalid(path.Child("key"), secret.Key, "source secret key must be defined"))
				}
			}

			if source.InLine != nil {
				unionCount++
			}

			if source.UseDefaultCAs != nil && *source.UseDefaultCAs {
				unionCount++
				defaultCAsCount++
			}

			if unionCount != 1 {
				el = append(el, field.Forbidden(
					path, fmt.Sprintf("must define exactly one source type for each item but found %d defined types", unionCount),
				))
			}
		}

		if defaultCAsCount > 1 {
			el = append(el, field.Forbidden(
				path,
				fmt.Sprintf("must request default CAs either once or not at all but got %d requests", defaultCAsCount),
			))
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

	if configMap := bundle.Spec.Target.ConfigMap; configMap == nil {
		el = append(el, field.Invalid(path.Child("target", "configMap"), configMap, "target configMap must be defined"))
	} else if len(configMap.Key) == 0 {
		el = append(el, field.Invalid(path.Child("target", "configMap", "key"), configMap.Key, "target configMap key must be defined"))
	} else if bundle.Spec.Target.AdditionalFormats != nil && bundle.Spec.Target.AdditionalFormats.JKS != nil {
		if bundle.Spec.Target.AdditionalFormats.JKS.Key == configMap.Key {
			el = append(el, field.Invalid(path.Child("target", "additionalFormats", "jks", "key"), bundle.Spec.Target.AdditionalFormats.JKS.Key, "target JKS key must be different to configMap key"))
		}
	}

	if nsSel := bundle.Spec.Target.NamespaceSelector; nsSel != nil && len(nsSel.MatchLabels) > 0 {
		if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSel.MatchLabels}); err != nil {
			el = append(el, field.Invalid(path.Child("target", "namespaceSelector", "matchLabels"), nsSel.MatchLabels, err.Error()))
		}
	}

	path = field.NewPath("status")

	conditionTypes := make(map[trustapi.BundleConditionType]struct{})
	for i, condition := range bundle.Status.Conditions {
		if _, ok := conditionTypes[condition.Type]; ok {
			el = append(el, field.Invalid(path.Child("conditions", "["+strconv.Itoa(i)+"]"), condition, "condition type already present on Bundle"))
		}
		conditionTypes[condition.Type] = struct{}{}
	}

	return warnings, el.ToAggregate()

}
