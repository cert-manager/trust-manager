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
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/kubernetes"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle"
	"github.com/cert-manager/trust-manager/pkg/options"
	"github.com/cert-manager/trust-manager/pkg/webhook"
)

const (
	helpOutput = `trust-manager is an operator for distributing bundles in Kubernetes clusters

Sources are loaded by being defined in Bundle resources, and are concatenated
into an output bundle 'target', which can then be made available to all
services across a cluster.`
)

// NewCommand will return a new command instance for the trust-manager operator.
func NewCommand() *cobra.Command {
	opts := options.New()

	cmd := &cobra.Command{
		Use:   "trust-manager",
		Short: helpOutput,
		Long:  helpOutput,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Complete(); err != nil {
				return err
			}

			cl, err := kubernetes.NewForConfig(opts.RestConfig)
			if err != nil {
				return fmt.Errorf("error creating kubernetes client: %s", err.Error())
			}

			log := opts.NewLogger()
			klog.SetLogger(log)
			ctrl.SetLogger(log)

			eventBroadcaster := record.NewBroadcaster()
			eventBroadcaster.StartLogging(func(format string, args ...any) { log.V(3).Info(fmt.Sprintf(format, args...)) })
			eventBroadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: cl.CoreV1().Events("")})

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        trustapi.GlobalScheme,
				EventBroadcaster:              eventBroadcaster,
				LeaderElection:                true,
				LeaderElectionID:              "trust-manager-leader-election",
				LeaderElectionReleaseOnCancel: true,
				LeaseDuration:                 &opts.LeaseDuration,
				RenewDeadline:                 &opts.RenewDeadline,
				ReadinessEndpointName:         opts.ReadyzPath,
				HealthProbeBindAddress:        fmt.Sprintf("0.0.0.0:%d", opts.ReadyzPort),
				WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
					Port:    opts.Webhook.Port,
					Host:    opts.Webhook.Host,
					CertDir: opts.Webhook.CertDir,
				}),
				Metrics: server.Options{
					BindAddress: fmt.Sprintf("0.0.0.0:%d", opts.MetricsPort),
				},
				Cache: cache.Options{
					ReaderFailOnMissingInformer: true,
					ByObject: map[client.Object]cache.ByObject{
						&trustapi.Bundle{}:  {},
						&corev1.Namespace{}: {},
						&corev1.ConfigMap{}: {
							// Only cache full ConfigMaps in the "watched" namespace.
							// Target ConfigMaps have a dedicated cache
							Namespaces: map[string]cache.Config{
								opts.Bundle.Namespace: {},
							},
						},
						&corev1.Secret{}: {
							// Only cache full Secrets in the "watched" namespace.
							// Target Secrets have a dedicated cache
							Namespaces: map[string]cache.Config{
								opts.Bundle.Namespace: {},
							},
						},
					},
				},
			})
			if err != nil {
				return fmt.Errorf("failed to create manager: %w", err)
			}

			targetCache, err := cache.New(mgr.GetConfig(), cache.Options{
				HTTPClient:                  mgr.GetHTTPClient(),
				Scheme:                      mgr.GetScheme(),
				Mapper:                      mgr.GetRESTMapper(),
				ReaderFailOnMissingInformer: true,
				DefaultLabelSelector: func() labels.Selector {
					targetRequirement, err := labels.NewRequirement(trustapi.BundleLabelKey, selection.Exists, nil)
					if err != nil {
						panic(fmt.Errorf("failed to create target label requirement: %w", err))
					}

					return labels.NewSelector().Add(*targetRequirement)
				}(),
			})
			if err != nil {
				return fmt.Errorf("failed to create target cache: %w", err)
			}

			if err := mgr.Add(targetCache); err != nil {
				return fmt.Errorf("failed to add target cache to manager: %w", err)
			}

			// Add readiness check that the manager's informers have been synced.
			if err := mgr.AddReadyzCheck("informers_synced", func(req *http.Request) error {
				if mgr.GetCache().WaitForCacheSync(req.Context()) {
					return nil
				}
				return errors.New("informers not synced")
			}); err != nil {
				return fmt.Errorf("failed to add readiness check: %w", err)
			}

			ctx := ctrl.SetupSignalHandler()

			// Add Bundle controller to manager.
			if err := bundle.AddBundleController(ctx, mgr, opts.Bundle, targetCache); err != nil {
				return fmt.Errorf("failed to register Bundle controller: %w", err)
			}

			// Register webhook handlers with manager.
			log.Info("registering webhook endpoints")
			if err := webhook.Register(mgr); err != nil {
				return fmt.Errorf("failed to register webhook: %w", err)
			}

			// Start all runnables and controller
			return mgr.Start(ctx)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
