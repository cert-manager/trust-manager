/*
Copyright 2026 The cert-manager Authors.

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

package metrics

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/source"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
)

var (
	caSSLNotBefore = prometheus.NewDesc("certmanager_ssl_ca_not_before", "A Unix timestamp of the date when the CA validity begins", []string{"serial_number", "subject_common_name", "bundle_name", "kind", "name", "key"}, nil)
	caSSLNotAfter  = prometheus.NewDesc("certmanager_ssl_ca_not_after", "A Unix timestamp of the date when the CA validity ends", []string{"serial_number", "subject_common_name", "bundle_name", "kind", "name", "key"}, nil)
)

type BundleCollector struct {
	logger               logr.Logger
	opts                 controller.Options
	client               client.Client
	pkg                  *fspkg.Package
	caSSLNotBeforeMetric *prometheus.Desc
	caSSLNotAfterMetric  *prometheus.Desc
}

func NewBundleCollector(log logr.Logger, opts controller.Options, client client.Client, pkg *fspkg.Package) prometheus.Collector {
	return &BundleCollector{
		logger:               log.WithName("Metrics"),
		opts:                 opts,
		client:               client,
		pkg:                  pkg,
		caSSLNotBeforeMetric: caSSLNotBefore,
		caSSLNotAfterMetric:  caSSLNotAfter,
	}
}

func (bc BundleCollector) Describe(desc chan<- *prometheus.Desc) {
	desc <- bc.caSSLNotBeforeMetric
	desc <- bc.caSSLNotAfterMetric
}

func (bc BundleCollector) Collect(ch chan<- prometheus.Metric) {
	bundles := v1alpha1.BundleList{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := bc.client.List(ctx, &bundles)
	if err != nil {
		bc.logger.V(5).Error(err, "failed to list bundles")
		return
	}

	bc.reportBundleMetrics(ctx, ch, bundles)
}

func (bc BundleCollector) reportBundleMetrics(ctx context.Context, ch chan<- prometheus.Metric, bundles v1alpha1.BundleList) {
	for i := range bundles.Items {
		bundle := bundles.Items[i]
		builder := source.BundleBuilder{
			Reader:         bc.client,
			Options:        bc.opts,
			DefaultPackage: bc.pkg,
		}
		bundleData, err := builder.BuildBundle(ctx, bundle.Spec.Sources)
		if err != nil {
			bc.logger.V(5).Error(err, "failed to build bundle")
			continue
		}

		certificates := bundleData.CertPool.Certificates()
		metrics := make([]prometheus.Metric, 0, len(certificates)*2)

		for j := range certificates {
			s := certificates[j]
			meta, err := bundleData.GetMetadata(s)
			if err != nil {
				bc.logger.Error(err, "failed to get metadata")
				continue
			}
			metrics = append(metrics, buildMetric(s, bundle.Name, string(meta.Kind), meta.Name, meta.Key)...)
		}

		for _, metric := range metrics {
			ch <- metric
		}
	}
}

func buildMetric(cert *x509.Certificate, bundleName string, sourceKind string, sourceName, sourceKey string) []prometheus.Metric {
	metrics := make([]prometheus.Metric, 0, 2)
	notAfter := prometheus.MustNewConstMetric(
		caSSLNotAfter,
		prometheus.GaugeValue,
		float64(cert.NotAfter.Unix()),
		cert.SerialNumber.String(),
		cert.Subject.CommonName,
		bundleName,
		sourceKind,
		sourceName,
		sourceKey,
	)
	metrics = append(metrics, notAfter)
	notBefore := prometheus.MustNewConstMetric(
		caSSLNotBefore,
		prometheus.GaugeValue,
		float64(cert.NotBefore.Unix()),
		cert.SerialNumber.String(),
		cert.Subject.CommonName,
		bundleName,
		sourceKind,
		sourceName,
		sourceKey,
	)
	metrics = append(metrics, notBefore)
	return metrics
}
