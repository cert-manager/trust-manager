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
	"crypto/tls"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/cert-manager/trust-manager/cmd/trust-manager/app/options"
	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle"
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

			tlsOptions, err := GetTLSOptions(opts.TLSConfig)
			if err != nil {
				return fmt.Errorf("invalid flags: %s", err.Error())
			}

			log := opts.NewLogger()
			klog.SetLogger(log)
			ctrl.SetLogger(log)

			scheme := runtime.NewScheme()
			utilruntime.Must(clientgoscheme.AddToScheme(scheme))
			utilruntime.Must(trustapi.AddToScheme(scheme))

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        scheme,
				LeaderElection:                opts.LeaderElectionConfig.Enabled,
				LeaderElectionID:              "trust-manager-leader-election",
				LeaderElectionReleaseOnCancel: true,
				LeaseDuration:                 &opts.LeaderElectionConfig.LeaseDuration,
				RenewDeadline:                 &opts.LeaderElectionConfig.RenewDeadline,
				ReadinessEndpointName:         opts.ReadyzPath,
				HealthProbeBindAddress:        fmt.Sprintf("0.0.0.0:%d", opts.ReadyzPort),
				WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
					Port:    opts.Webhook.Port,
					Host:    opts.Webhook.Host,
					CertDir: opts.Webhook.CertDir,
					TLSOpts: tlsOptions,
				}),
				Metrics: server.Options{
					BindAddress: fmt.Sprintf("0.0.0.0:%d", opts.MetricsPort),
				},
				Cache: bundle.CacheOpts(opts.Bundle, opts.TargetNamespaces),
			})
			if err != nil {
				return fmt.Errorf("failed to create manager: %w", err)
			}

			if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
				return fmt.Errorf("failed to add webhook ready check: %v", err)
			}
			if err := mgr.AddHealthzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
				return fmt.Errorf("failed to add webhook health check: %v", err)
			}

			ctx := ctrl.SetupSignalHandler()
			logf.IntoContext(ctx, log)

			// Add Bundle controller to manager.
			if err := bundle.SetupWithManager(ctx, mgr, opts.Bundle, opts.TargetNamespaces); err != nil {
				return fmt.Errorf("failed to register Bundle controller: %w", err)
			}

			// Register webhook handlers with manager.
			log.Info("registering webhook endpoints")
			if err := webhook.SetupWebhookWithManager(mgr); err != nil {
				return fmt.Errorf("failed to register webhook: %w", err)
			}

			// Start all runnables and controller
			return mgr.Start(ctx)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}

func GetTLSOptions(config options.TLSConfig) ([]func(*tls.Config), error) {
	var tlsOptions []func(config *tls.Config)

	if config.MinVersion != "" {
		tlsVersion, err := cliflag.TLSVersion(config.MinVersion)
		if err != nil {
			return nil, err
		}
		tlsOptions = append(tlsOptions, func(cfg *tls.Config) {
			cfg.MinVersion = tlsVersion
		})
	}

	if len(config.CipherSuites) > 0 {
		suites, err := cliflag.TLSCipherSuites(config.CipherSuites)
		if err != nil {
			return nil, err
		}
		tlsOptions = append(tlsOptions, func(cfg *tls.Config) {
			cfg.CipherSuites = suites
		})
	}

	return tlsOptions, nil
}
