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
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/options"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test/dummy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	EventuallyTimeout      = "90s"
	EventuallyPollInterval = "100ms"
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
// Resulting Bundle will sync to the Target "target-key".
func DefaultTrustData() TestData {
	var td TestData
	td.Sources.ConfigMap.Key = "configMap-key"
	td.Sources.ConfigMap.Data = dummy.TestCertificate1
	td.Sources.Secret.Key = "secret-key"
	td.Sources.Secret.Data = dummy.TestCertificate2
	td.Sources.InLine.Data = dummy.TestCertificate3
	td.Target.Key = "target-key"
	return td
}

// newTestBundle creates a new Bundle in the API using the input test data.
// Returns the create Bundle object.
func newTestBundle(ctx context.Context, cl client.Client, opts options.Bundle, td TestData, targetType string) *trustapi.Bundle {
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
						Name: configMap.Name,
						Key:  td.Sources.ConfigMap.Key,
					},
				},

				{
					Secret: &trustapi.SourceObjectKeySelector{
						Name: secret.Name,
						Key:  td.Sources.Secret.Key,
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
	if targetType == "ConfigMap" {
		bundle.Spec.Target = trustapi.BundleTarget{
			ConfigMap: &td.Target,
		}
	} else if targetType == "Secret" {
		bundle.Spec.Target = trustapi.BundleTarget{
			Secret: &td.Target,
		}
	}
	Expect(cl.Create(ctx, &bundle)).NotTo(HaveOccurred())

	return &bundle
}

// NewTestBundleSecretTarget creates a new Bundle in the API using the input test data.
// Returns the create Bundle object.
func NewTestBundleSecretTarget(ctx context.Context, cl client.Client, opts options.Bundle, td TestData) *trustapi.Bundle {
	return newTestBundle(ctx, cl, opts, td, "Secret")
}

// newTestBundleConfigMapTarget creates a new Bundle in the API using the input test data with target set to ConfigMap.
// Returns the create Bundle object.
func NewTestBundleConfigMapTarget(ctx context.Context, cl client.Client, opts options.Bundle, td TestData) *trustapi.Bundle {
	return newTestBundle(ctx, cl, opts, td, "ConfigMap")
}

func checkBundleSyncedInternal(ctx context.Context, cl client.Client, bundleName string, namespace string, comparator func(string) error) error {
	var bundle trustapi.Bundle
	Expect(cl.Get(ctx, client.ObjectKey{Name: bundleName}, &bundle)).NotTo(HaveOccurred())

	var gotData string
	switch {
	case bundle.Spec.Target.ConfigMap != nil:
		var configMap corev1.ConfigMap
		if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: bundle.Name}, &configMap); err != nil {
			return fmt.Errorf("failed to get configMap %s/%s when checking bundle sync: %w", namespace, bundle.Name, err)
		}
		gotData = configMap.Data[bundle.Spec.Target.ConfigMap.Key]
	case bundle.Spec.Target.Secret != nil:
		var secret corev1.Secret
		if err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: bundle.Name}, &secret); err != nil {
			return fmt.Errorf("failed to get secret %s/%s when checking bundle sync: %w", namespace, bundle.Name, err)
		}
		gotData = string(secret.Data[bundle.Spec.Target.Secret.Key])
	default:
		return fmt.Errorf("invalid bundle spec targets: %v", bundle.Spec.Target)
	}

	if err := comparator(gotData); err != nil {
		return fmt.Errorf("configMap %s/%s didn't have expected value: %w", namespace, bundle.Name, err)
	}

	for _, condition := range bundle.Status.Conditions {
		if condition.Status == metav1.ConditionTrue && bundle.Generation == condition.ObservedGeneration {
			return nil
		}
	}

	return fmt.Errorf("couldn't find a success condition on bundle status with expected observedGeneration %d", bundle.Generation)
}

// CheckBundleSynced returns nil if the given Bundle has synced the expected data to the given
// namespace, or else returns a descriptive error if that's not the case.
// - Skips Namespaces that are Terminating since targets are not synced there.
// - Ensures the Bundle status has been updated with the appropriate target.
// - Ensures the Bundle has the correct status condition with the same ObservedGeneration as the current Generation.
func CheckBundleSynced(ctx context.Context, cl client.Client, bundleName string, namespace string, expectedData string) error {
	return checkBundleSyncedInternal(ctx, cl, bundleName, namespace, func(got string) error {
		if expectedData != got {
			// TODO: also detail "expected" and "got" data, but don't just dump the raw PEM values
			// maybe parse certs and transform into a user friendly representation for easier visual inspection
			return fmt.Errorf("received data didn't exactly match expected data")
		}

		return nil
	})
}

// CheckBundleSyncedContains is similar to CheckBundleSynced but only checks that the synced bundle contains the given data,
// along with checking that the rest of the data contains at least one valid certificate
func CheckBundleSyncedContains(ctx context.Context, cl client.Client, name string, namespace string, containedData string) error {
	return checkBundleSyncedInternal(ctx, cl, name, namespace, func(got string) error {
		var block *pem.Block
		certBytes := []byte(containedData)

		for {
			block, certBytes = pem.Decode(certBytes)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				return fmt.Errorf("couldn't decode PEM block containing certificate")
			}

			if !(strings.Contains(got, string(bytes.Trim(pem.EncodeToMemory(block), "\n")))) {
				return fmt.Errorf("did not find all certs")
			}
		}

		certBytes = []byte(got)
		// check that there are a nonzero number of valid certs remaining
		found := false

		for {
			block, certBytes = pem.Decode(certBytes)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				return fmt.Errorf("couldn't decode PEM block containing certificate")
			}

			if strings.Contains(containedData, string(bytes.Trim(pem.EncodeToMemory(block), "\n"))) {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("did not find additional valid certs")
		}

		return nil
	})
}

func checkBundleSyncedAllNamespacesInternal(ctx context.Context, cl client.Client, checker func(namespace string) error) error {
	var namespaceList corev1.NamespaceList
	if err := cl.List(ctx, &namespaceList); err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	var errs []error

	for _, namespace := range namespaceList.Items {
		// Skip terminating namespaces since Bundle won't be synced there
		if namespace.Status.Phase == corev1.NamespaceTerminating {
			continue
		}

		if err := checker(namespace.Name); err != nil {
			errs = append(errs, fmt.Errorf("namespace %q has not synced: %w", namespace.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("bundle has not synced all namespaces; errors: %w", utilerrors.NewAggregate(errs))
	}

	return nil
}

// CheckBundleSyncedAllNamespaces calls CheckBundleSynced for all namespaces and returns an error if any of them failed
func CheckBundleSyncedAllNamespaces(ctx context.Context, cl client.Client, name string, expectedData string) error {
	return checkBundleSyncedAllNamespacesInternal(ctx, cl, func(namespace string) error {
		return CheckBundleSynced(ctx, cl, name, namespace, expectedData)
	})
}

// CheckBundleSyncedAllNamespacesContains calls CheckBundleSyncedContains for all namespaces and returns an error if any of them failed
func CheckBundleSyncedAllNamespacesContains(ctx context.Context, cl client.Client, name string, containedData string) error {
	return checkBundleSyncedAllNamespacesInternal(ctx, cl, func(namespace string) error {
		return CheckBundleSyncedContains(ctx, cl, name, namespace, containedData)
	})
}

// EventuallyBundleHasSyncedToNamespace tries to assert that the given bundle is synced correctly to the given namespace
// until either the assertion passes or the timeout is triggered
func EventuallyBundleHasSyncedToNamespace(ctx context.Context, cl client.Client, bundleName string, namespace string, expectedData string) {
	Eventually(
		CheckBundleSynced,
		EventuallyTimeout, EventuallyPollInterval, ctx,
	).WithArguments(
		ctx, cl, bundleName, namespace, expectedData,
	).Should(Succeed(), fmt.Sprintf("checking bundle %s has synced to namespace %s", bundleName, namespace))
}

// EventuallyBundleHasSyncedToNamespaceContains tries to assert that the given bundle is synced correctly to the given namespace
// until either the assertion passes or the timeout is triggered
func EventuallyBundleHasSyncedToNamespaceContains(ctx context.Context, cl client.Client, bundleName string, namespace string, containedData string) {
	Eventually(
		CheckBundleSyncedContains,
		EventuallyTimeout, EventuallyPollInterval, ctx,
	).WithArguments(
		ctx, cl, bundleName, namespace, containedData,
	).Should(Succeed(), fmt.Sprintf("checking bundle %s has synced to namespace %s", bundleName, namespace))
}

// EventuallyBundleHasSyncedAllNamespaces tries to assert that the given bundle is synced correctly to every namespace
// until either the assertion passes or the timeout is triggered
func EventuallyBundleHasSyncedAllNamespaces(ctx context.Context, cl client.Client, bundleName string, expectedData string) {
	Eventually(
		CheckBundleSyncedAllNamespaces,
		EventuallyTimeout, EventuallyPollInterval, ctx,
	).WithArguments(
		ctx, cl, bundleName, expectedData,
	).Should(Succeed(), fmt.Sprintf("checking bundle %s has synced to all namespaces", bundleName))
}

// EventuallyBundleHasSyncedAllNamespacesContains tries to assert that the given bundle is synced correctly to every namespace
// until either the assertion passes or the timeout is triggered
func EventuallyBundleHasSyncedAllNamespacesContains(ctx context.Context, cl client.Client, bundleName string, containedData string) {
	Eventually(
		CheckBundleSyncedAllNamespacesContains,
		EventuallyTimeout, EventuallyPollInterval, ctx,
	).WithArguments(
		ctx, cl, bundleName, containedData,
	).Should(Succeed(), fmt.Sprintf("checking bundle %s has synced to all namespaces with correct starting data", bundleName))
}

// CheckJKSFileSynced ensures that the given JKS data
func CheckJKSFileSynced(jksData []byte, expectedPassword string, expectedCertPEMData string) error {
	reader := bytes.NewReader(jksData)
	certPool := util.NewCertPool(util.WithFilteredExpiredCerts(false))

	ks := jks.New()

	err := ks.Load(reader, []byte(expectedPassword))
	if err != nil {
		return err
	}

	err = certPool.AddCertsFromPEM([]byte(expectedCertPEMData))
	if err != nil {
		return fmt.Errorf("invalid PEM data passed to CheckJKSFileSynced: %s", err)
	}

	// TODO: check that the cert content matches expectedCertPEMData exactly, not just
	// that the count is the same

	aliasCount := len(ks.Aliases())
	expectedPEMCount := certPool.Size()

	if aliasCount != expectedPEMCount {
		return fmt.Errorf("expected %d certificates in JKS but found %d", expectedPEMCount, aliasCount)
	}

	return nil
}
