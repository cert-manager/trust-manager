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
	"k8s.io/client-go/kubernetes"
	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cert-manager/trust-manager/cmd/app/options"
	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle"
	"github.com/cert-manager/trust-manager/pkg/webhook"
)

const (
	helpOutput = "Operator for distributing bundles from a trust Namespace across a Kubernetes Cluster to be made available to all services"
)

// NewCommand will return a new command instance for the trust operator.
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

			mlog := opts.Logr.WithName("manager")
			eventBroadcaster := record.NewBroadcaster()
			eventBroadcaster.StartLogging(func(format string, args ...interface{}) { mlog.V(3).Info(fmt.Sprintf(format, args...)) })
			eventBroadcaster.StartRecordingToSink(&clientv1.EventSinkImpl{Interface: cl.CoreV1().Events("")})

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        trustapi.GlobalScheme,
				EventBroadcaster:              eventBroadcaster,
				LeaderElection:                true,
				LeaderElectionNamespace:       opts.Bundle.Namespace,
				NewCache:                      bundle.NewCacheFunc(opts.Bundle),
				ClientDisableCacheFor:         bundle.ClientDisableCacheFor(),
				LeaderElectionID:              "trust-manager-leader-election",
				LeaderElectionReleaseOnCancel: true,
				ReadinessEndpointName:         opts.ReadyzPath,
				HealthProbeBindAddress:        fmt.Sprintf("0.0.0.0:%d", opts.ReadyzPort),
				Port:                          opts.Webhook.Port,
				Host:                          opts.Webhook.Host,
				CertDir:                       opts.Webhook.CertDir,
				MetricsBindAddress:            fmt.Sprintf("0.0.0.0:%d", opts.MetricsPort),
				Logger:                        mlog,
			})
			if err != nil {
				return fmt.Errorf("failed to create manager: %w", err)
			}

			// Add readiness check that the manager's informers have been synced.
			mgr.AddReadyzCheck("informers_synced", func(req *http.Request) error {
				if mgr.GetCache().WaitForCacheSync(req.Context()) {
					return nil
				}
				return errors.New("informers not synced")
			})

			ctx := ctrl.SetupSignalHandler()

			// Add Bundle controller to manager.
			if err := bundle.AddBundleController(ctx, mgr, opts.Bundle); err != nil {
				return fmt.Errorf("failed to register Bundle controller: %w", err)
			}

			// Register webhook handlers with manager.
			webhook.Register(mgr, webhook.Options{Log: opts.Logr.WithName("webhook")})

			// Start all runnables and controller
			return mgr.Start(ctx)
		},
	}

	opts = opts.Prepare(cmd)

	return cmd
}
