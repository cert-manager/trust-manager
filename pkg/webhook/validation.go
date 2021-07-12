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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-logr/logr"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
)

// TODO
type validator struct {
	log logr.Logger

	lister  client.Reader
	decoder *admission.Decoder

	lock sync.RWMutex
}

func (v *validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := v.log.WithValues("name", req.Name)
	log.V(2).Info("received validation request")

	var bundle trustapi.Bundle

	v.lock.RLock()
	err := v.decoder.Decode(req, &bundle)
	v.lock.RUnlock()

	if err != nil {
		log.Error(err, "failed to decode Bundle")
		return admission.Errored(http.StatusBadRequest, err)
	}

	var el field.ErrorList
	path := field.NewPath("spec")

	if len(bundle.Spec.Sources) == 0 {
		el = append(el, field.Forbidden(path.Child("sources"), "must define at lease one source"))
	} else {
		// TODO: move to openAPI validation

		path := path.Child("sources")

		for i, source := range bundle.Spec.Sources {
			path := path.Child(strconv.Itoa(i))
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

			if unionCount != 1 {
				el = append(el, field.Forbidden(path, "must define exactly one source type for each item"))
			}
		}
	}

	if target := bundle.Spec.Target.ConfigMap; target != nil {
		path := path.Child("sources")
		for i, source := range bundle.Spec.Sources {
			if source.ConfigMap != nil && source.ConfigMap.Name == bundle.Name && source.ConfigMap.Key == target.Key {
				el = append(el, field.Forbidden(path.Child(fmt.Sprintf("[%d]", i), source.ConfigMap.Name, source.ConfigMap.Key), "cannot define the same source as target"))
			}
		}
	}

	if configMap := bundle.Spec.Target.ConfigMap; configMap == nil {
		el = append(el, field.Invalid(path.Child("target", "configMap"), configMap, "target configMap must be defined"))
	} else if len(configMap.Key) == 0 {
		el = append(el, field.Invalid(path.Child("target", "configMap", "key"), configMap.Key, "target configMap key must be defined"))
	}

	if configMap := bundle.Spec.Target.ConfigMap; configMap != nil {
		var existingBundleList trustapi.BundleList
		if err := v.lister.List(ctx, &existingBundleList); err != nil {
			log.Error(err, "failed to list existing Bundles")
			return admission.Errored(http.StatusInternalServerError, errors.New("failed to list existing Bundle resources"))
		}

		for _, existingBundle := range existingBundleList.Items {
			if existingBundle.Name == bundle.Name {
				continue
			}

			if apiequality.Semantic.DeepEqual(bundle.Spec.Target, existingBundle.Spec.Target) {
				el = append(el, field.Invalid(path.Child("target", "configMap"), configMap, fmt.Sprintf("cannot use the same target as another Bundle %q", existingBundle.Name)))
			}
		}
	}

	if err := el.ToAggregate(); err != nil {
		log.V(2).Info("denied request", "reason", el.ToAggregate().Error())
		return admission.Denied(el.ToAggregate().Error())
	}

	log.V(2).Info("allowed request")
	return admission.Allowed("Bundle validated")
}

func (v *validator) InjectDecoder(d *admission.Decoder) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	v.decoder = d
	return nil
}

// check is used by the shared readiness manager to expose whether the server
// is ready.
func (v *validator) check(_ *http.Request) error {
	v.lock.RLock()
	defer v.lock.RUnlock()

	if v.decoder != nil {
		return nil
	}

	return errors.New("not ready")
}
