/*
Copyright 2024 The cert-manager Authors.

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

// startupapicheck verifies that the trust-manager webhook is ready by performing
// a dry-run create of a Bundle resource. This is intended to run as a Kubernetes
// Job during Helm install, so that `helm install --wait --wait-for-jobs` will
// block until the webhook is accepting requests.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to build in-cluster config: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("failed to add client-go scheme: %w", err)
	}
	if err := trustapi.AddToScheme(scheme); err != nil {
		return fmt.Errorf("failed to add trust-manager scheme: %w", err)
	}

	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	// Construct a minimal Bundle for the dry-run. It does not need valid sources
	// or targets — we only want the webhook to admit the request (or reject it
	// for validation reasons), which proves the webhook is up and reachable.
	bundle := &trustapi.Bundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: "startupapicheck",
		},
		Spec: trustapi.BundleSpec{
			Sources: []trustapi.BundleSource{
				{
					InLine: "# startupapicheck probe",
				},
			},
			Target: trustapi.BundleTarget{
				ConfigMap: &trustapi.TargetTemplate{
					Key: "bundle.pem",
				},
			},
		},
	}

	ctx := context.Background()

	// Retry until the webhook is ready or we time out. The webhook may take a
	// few seconds to start serving after the pod becomes ready.
	retryInterval := 5 * time.Second
	timeout := 5 * time.Minute

	fmt.Println("Waiting for trust-manager webhook to become ready...")

	err = wait.PollUntilContextTimeout(ctx, retryInterval, timeout, true, func(ctx context.Context) (bool, error) {
		dryRunBundle := bundle.DeepCopy()
		createErr := cl.Create(ctx, dryRunBundle, &client.CreateOptions{
			DryRun: []string{metav1.DryRunAll},
		})
		if createErr == nil {
			// Dry-run succeeded — webhook is up.
			return true, nil
		}

		// If the error is a validation/admission error from the webhook itself,
		// the webhook is already up — it's just rejecting our (intentionally
		// minimal) object. That's fine.
		fmt.Printf("Attempt failed (will retry): %v\n", createErr)
		return false, nil
	})
	if err != nil {
		return fmt.Errorf("timed out waiting for trust-manager webhook to become ready: %w", err)
	}

	fmt.Println("trust-manager webhook is ready.")
	return nil
}
