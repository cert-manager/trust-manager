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

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilrand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/dynamic"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func NewStartupAPICheckCommand() *cobra.Command {
	var (
		timeout  time.Duration
		interval time.Duration

		kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	)

	cmd := &cobra.Command{
		Use:   "startupapicheck",
		Short: "Wait for trust-manager to be ready to accept Bundle resources (CRD + webhook ready)",
		RunE: func(cmd *cobra.Command, args []string) error {
			restCfg, err := kubeConfigFlags.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("failed to build kubernetes rest config: %w", err)
			}

			dc, err := dynamic.NewForConfig(restCfg)
			if err != nil {
				return fmt.Errorf("failed to create dynamic client: %w", err)
			}

			// Bundles are cluster-scoped.
			gvr := schema.GroupVersionResource{
				Group:    "trust.cert-manager.io",
				Version:  "v1alpha1",
				Resource: "bundles",
			}

			// Use DryRun so we don't persist anything, but still exercise admission.
			name := "startupapicheck-" + utilrand.String(8)

			bundle := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "trust.cert-manager.io/v1alpha1",
					"kind":       "Bundle",
					"metadata": map[string]any{
						"name": name,
					},
					"spec": map[string]any{
						"sources": []any{
							map[string]any{
								// Simple non-empty string; avoids requiring default packages etc.
								"inLine": "startupapicheck",
							},
						},
						"target": map[string]any{
							"configMap": map[string]any{
								"key": "bundle.pem",
							},
						},
					},
				},
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			lastLog := time.Time{}

			return wait.PollUntilContextCancel(ctx, interval, true, func(ctx context.Context) (bool, error) {
				_, err := dc.Resource(gvr).Create(ctx, bundle, metav1.CreateOptions{
					DryRun: []string{"All"},
				})
				if err != nil {
					// Don't spam logs every poll; log ~every 10s.
					if time.Since(lastLog) > 10*time.Second {
						fmt.Fprintf(cmd.ErrOrStderr(), "startupapicheck: waiting for API to accept Bundle (CRD+webhook): %v\n", err)
						lastLog = time.Now()
					}
					return false, nil
				}

				fmt.Fprintln(cmd.OutOrStdout(), "startupapicheck: success")
				return true, nil
			})
		},
	}

	cmd.Flags().DurationVar(&timeout, "timeout", time.Minute, "Timeout to wait for the API to be ready")
	cmd.Flags().DurationVar(&interval, "interval", 2*time.Second, "Polling interval between attempts")

	// Support running locally too.
	kubeConfigFlags.AddFlags(cmd.Flags())

	return cmd
}
