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

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

type MetricRegistrator struct {
	registry   metrics.RegistererGatherer
	collectors []prometheus.Collector
}

func NewRegistrator(registry metrics.RegistererGatherer) *MetricRegistrator {
	return &MetricRegistrator{
		registry:   registry,
		collectors: make([]prometheus.Collector, 0),
	}
}

func (m *MetricRegistrator) Add(collector prometheus.Collector) {
	m.collectors = append(m.collectors, collector)
}

func (m *MetricRegistrator) Start(ctx context.Context) error {
	for i := range m.collectors {
		err := m.registry.Register(m.collectors[i])
		if err != nil {
			return err
		}
	}
	<-ctx.Done()

	for i := range m.collectors {
		m.registry.Unregister(m.collectors[i])
	}

	return nil
}

func (m *MetricRegistrator) NeedLeaderElection() bool {
	return true
}
