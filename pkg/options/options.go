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

package options

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// Options is a struct to hold options for trust-manager
type Options struct {
	kubeConfigFlags *genericclioptions.ConfigFlags

	// ReadyzPort if the port used to expose Prometheus metrics.
	ReadyzPort int
	// ReadyzPath if the HTTP path used to expose Prometheus metrics.
	ReadyzPath string

	// MetricsPort is the port for exposing Prometheus metrics on 0.0.0.0 on the
	// path '/metrics'.
	MetricsPort int

	// RestConfig is the shared based rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	// Webhook are options specific to the Kubernetes Webhook.
	Webhook

	// Bundle are options specific to the Bundle controller.
	Bundle Bundle

	// log are options controlling logging
	log logOptions

	// Leader election lease duration
	LeaseDuration time.Duration

	// Leader election lease renew duration
	RenewDeadline time.Duration
}

type logOptions struct {
	format logFormat
	level  int
}

const (
	logFormatText logFormat = "text"
	logFormatJSON logFormat = "json"
)

type logFormat string

// String is used both by fmt.Print and by Cobra in help text
func (e *logFormat) String() string {
	if len(*e) == 0 {
		return string(logFormatText)
	}
	return string(*e)
}

// Set must have pointer receiver to avoid changing the value of a copy
func (e *logFormat) Set(v string) error {
	switch v {
	case "text", "json":
		*e = logFormat(v)
		return nil
	default:
		return errors.New(`must be one of "text" or "json"`)
	}
}

// Type is only used in help text
func (e *logFormat) Type() string {
	return "string"
}

// Webhook holds options specific to running the trust Webhook service.
type Webhook struct {
	Host    string
	Port    int
	CertDir string
}

// New constructs a new Options.
func New() *Options {
	return new(Options)
}

// Prepare adds Options flags to the CLI command.
func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

// NewLogger constructs a new root logger based on the CLI flags.
func (o *Options) NewLogger() logr.Logger {
	opts := &slog.HandlerOptions{
		// To avoid a breaking change in application configuration,
		// we negate the (configured) logr verbosity level to get the corresponding slog level
		Level: slog.Level(-o.log.level),
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if o.log.format == logFormatJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))

	return logr.FromSlogHandler(handler)
}

// Complete will populate the remaining Options from the CLI flags. Must be run
// before consuming Options.
func (o *Options) Complete() error {
	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	return nil
}

// addFlags add all Options flags to the given command.
func (o *Options) addFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.addBundleFlags(nfs.FlagSet("Bundle"))
	o.addLoggingFlags(nfs.FlagSet("Logging"))
	o.addWebhookFlags(nfs.FlagSet("Webhook"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), nfs, 0)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), nfs, 0)
	})

	fs := cmd.Flags()
	for _, f := range nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) addAppFlags(fs *pflag.FlagSet) {
	fs.IntVar(&o.ReadyzPort,
		"readiness-probe-port", 6060,
		"Port to expose the readiness probe.")

	fs.StringVar(&o.ReadyzPath,
		"readiness-probe-path", "/readyz",
		"HTTP path to expose the readiness probe server.")

	fs.DurationVar(&o.LeaseDuration,
		"leader-election-lease-duration", time.Second*15,
		"Lease duration for leader election")

	fs.DurationVar(&o.RenewDeadline,
		"leader-election-renew-deadline", time.Second*10,
		"Lease renew deadline for leader election")

	fs.IntVar(&o.MetricsPort,
		"metrics-port", 9402,
		"Port to expose Prometheus metrics on 0.0.0.0 on path '/metrics'.")
}

func (o *Options) addBundleFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Bundle.Namespace,
		"trust-namespace", "cert-manager",
		"Namespace to source trust bundles from.")

	fs.StringVar(&o.Bundle.DefaultPackageLocation,
		"default-package-location", "",
		"Path to a JSON file containing the default certificate package. If set, must be a valid package.")

	fs.BoolVar(&o.Bundle.SecretTargetsEnabled,
		"secret-targets-enabled", false,
		"Controls if secret targets are enabled in the Bundle API.")

	fs.BoolVar(&o.Bundle.FilterExpiredCerts,
		"filter-expired-certificates", false,
		"Filter expired certificates from the bundle.")
}

func (o *Options) addLoggingFlags(fs *pflag.FlagSet) {
	fs.Var(&o.log.format,
		"log-format",
		"Log format (text or json)")

	fs.IntVarP(&o.log.level,
		"log-level", "v", 1,
		"Log level (1-5).")
}

func (o *Options) addWebhookFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Webhook.Host,
		"webhook-host", "0.0.0.0",
		"Host to serve webhook.")
	fs.IntVar(&o.Webhook.Port,
		"webhook-port", 6443,
		"Port to serve webhook.")
	fs.StringVar(&o.Webhook.CertDir,
		"webhook-certificate-dir", "/tls",
		"Directory where the Webhook certificate and private key are located. "+
			"Certificate and private key must be named 'tls.crt' and 'tls.key' "+
			"respectively.")
}

// Bundle hold options for the Bundle controller.
type Bundle struct {
	// Namespace is the trust Namespace that source data can be referenced.
	Namespace string

	// DefaultPackageLocation is the location on the filesystem from which the 'default'
	// certificate package should be loaded. If set, a valid package must be successfully
	// loaded in order for the controller to start. If unset, referring to the default
	// certificate package in a `Bundle` resource will cause that Bundle to error.
	DefaultPackageLocation string

	// SecretTargetsEnabled controls if secret targets are enabled in the Bundle API.
	SecretTargetsEnabled bool

	// FilterExpiredCerts controls if expired certificates are filtered from the bundle.
	FilterExpiredCerts bool
}
