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

package env

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust/pkg/bundle"
)

// TestData is used as a set of input data to a Bundle suite test. It
// represents a subset of the Bundle API spec.
type TestData struct {
	Sources struct {
		ConfigMap struct {
			trustapi.SourceObjectKeySelector
			Data string
		}
		Secret struct {
			trustapi.SourceObjectKeySelector
			Data string
		}
		InLine struct {
			Data string
		}
	}

	Target trustapi.KeySelector
}

// DefaultTrustData returns a well-known set of default data for a test.
// Resulting Bundle will sync "A\nB\nC\n" to the Target "target-key".
func DefaultTrustData() TestData {
	var td TestData
	td.Sources.ConfigMap.Key = "configMap-key"
	td.Sources.ConfigMap.Data = "A"
	td.Sources.Secret.Key = "secret-key"
	td.Sources.Secret.Data = "B"
	td.Sources.InLine.Data = "C"
	td.Target.Key = "target-key"
	return td
}

// newTestBundle creates a new Bundle in the API using the input test data.
// Returns the create Bundle object.
func NewTestBundle(ctx context.Context, cl client.Client, opts bundle.Options, td TestData) *trustapi.Bundle {
	By("creating trust Bundle")

	configMap := corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-bundle-",
			Namespace:    opts.Namespace,
		},
		Data: map[string]string{
			td.Sources.ConfigMap.Key: td.Sources.ConfigMap.Data,
		},
	}
	Expect(cl.Create(ctx, &configMap)).NotTo(HaveOccurred())

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-bundle-",
			Namespace:    opts.Namespace,
		},
		Data: map[string][]byte{
			td.Sources.Secret.Key: []byte(td.Sources.Secret.Data),
		},
	}
	Expect(cl.Create(ctx, &secret)).NotTo(HaveOccurred())

	bundle := trustapi.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-bundle-",
		},
		Spec: trustapi.BundleSpec{
			Sources: []trustapi.BundleSource{
				{
					ConfigMap: &trustapi.SourceObjectKeySelector{
						Name:        configMap.Name,
						KeySelector: trustapi.KeySelector{Key: td.Sources.ConfigMap.Key},
					},
				},

				{
					Secret: &trustapi.SourceObjectKeySelector{
						Name:        secret.Name,
						KeySelector: trustapi.KeySelector{Key: td.Sources.Secret.Key},
					},
				},

				{
					InLine: &td.Sources.InLine.Data,
				},
			},
			Target: trustapi.BundleTarget{
				ConfigMap: &td.Target,
			},
		},
	}
	Expect(cl.Create(ctx, &bundle)).NotTo(HaveOccurred())

	return &bundle
}

// BundleHasSynced will return true if the given Bundle has synced the expected
// data to targets in all namespaces.
// Skips Namespaces that are Terminating since targets are not synced there.
// Ensures the Bundle status has been updated with the appropriate target.
// Ensures the Bundle has the correct status condition with the same
// ObservedGeneration as the current Generation.
func BundleHasSynced(ctx context.Context, cl client.Client, name, namespace, expectedData string) bool {
	var bundle trustapi.Bundle
	Expect(cl.Get(ctx, client.ObjectKey{Name: name}, &bundle)).NotTo(HaveOccurred())

	var configMap corev1.ConfigMap
	Eventually(func() error {
		return cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: bundle.Name}, &configMap)
	}, "1s", "100ms").Should(BeNil(), "Waiting for ConfigMap to be created")

	if configMap.Data[bundle.Spec.Target.ConfigMap.Key] != expectedData {
		By(fmt.Sprintf("ConfigMap does not have expected data: %s/%s: EXPECTED[%q] GOT[%q]",
			namespace, bundle.Name, expectedData, configMap.Data[bundle.Spec.Target.ConfigMap.Key]))
		return false
	}

	if bundle.Status.Target == nil || !apiequality.Semantic.DeepEqual(*bundle.Status.Target, bundle.Spec.Target) {
		return false
	}

	for _, condition := range bundle.Status.Conditions {
		if condition.Status == corev1.ConditionTrue && bundle.Generation == condition.ObservedGeneration {
			return true
		}
	}

	return false
}

// BundleHasSyncedAllNamespaces calls BundleHasSynced for all namespaces.
func BundleHasSyncedAllNamespaces(ctx context.Context, cl client.Client, name, expectedData string) bool {
	var namespaceList corev1.NamespaceList
	Expect(cl.List(ctx, &namespaceList)).NotTo(HaveOccurred())

	for _, namespace := range namespaceList.Items {
		// Skip terminating namespaces since Bundle won't be synced there
		if namespace.Status.Phase == corev1.NamespaceTerminating {
			continue
		}

		return BundleHasSynced(ctx, cl, name, namespace.Name, expectedData)
	}

	return true
}
