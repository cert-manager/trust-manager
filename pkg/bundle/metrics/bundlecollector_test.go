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
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func newTestLogger(t *testing.T) logr.Logger {
	return funcr.New(func(prefix, args string) {
		t.Logf("%s: %s", prefix, args)
	}, funcr.Options{
		Verbosity: 10,
	})
}

func getDescName(desc *prometheus.Desc) string {
	descStr := desc.String()
	parts := strings.Split(descStr, "\"")
	if len(parts) >= 2 {
		return strings.TrimSuffix(parts[1], "\"")
	}
	return ""
}

func getMetricValue(m prometheus.Metric) float64 {
	dtoMetric := &dto.Metric{}
	err := m.Write(dtoMetric)
	if err != nil {
		return 0
	}
	if dtoMetric.GetGauge() != nil {
		return dtoMetric.GetGauge().GetValue()
	}
	return 0
}

func parseTestCertificate(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "should be able to decode PEM block")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "should be able to parse certificate")
	return cert
}

func Test_BundleCollector_Describe(t *testing.T) {
	tests := map[string]struct {
		expectedDescNames []string
	}{
		"should describe both not_before and not_after metrics": {
			expectedDescNames: []string{
				"certmanager_ssl_ca_not_before",
				"certmanager_ssl_ca_not_after",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logger := newTestLogger(t)
			scheme := runtime.NewScheme()
			require.NoError(t, trustapi.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				Build()

			collector := NewBundleCollector(logger, controller.Options{Namespace: "test"}, client, nil)

			descCh := make(chan *prometheus.Desc, 10)
			collector.Describe(descCh)
			close(descCh)

			var descs []*prometheus.Desc
			for desc := range descCh {
				descs = append(descs, desc)
			}

			require.Len(t, descs, len(tt.expectedDescNames))
			for i, expectedName := range tt.expectedDescNames {
				assert.Equal(t, expectedName, getDescName(descs[i]))
			}
		})
	}
}

func Test_BundleCollector_Collect(t *testing.T) {
	tests := map[string]struct {
		bundle         *trustapi.Bundle
		extraObjects   []client.Object
		namespace      string
		expectedLen    int
		defaultPackage *fspkg.Package
	}{
		"inLine source should collect metrics": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: dummy.TestCertificate1},
					},
				},
			},
			extraObjects: nil,
			namespace:    "test-namespace",
			expectedLen:  2,
		},
		"secret with key should collect metrics": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{Secret: &trustapi.SourceObjectKeySelector{
							Name: "my-secret",
							Key:  "ca.crt",
						}},
					},
				},
			},
			extraObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-secret",
						Namespace: "test-namespace",
					},
					Data: map[string][]byte{
						"ca.crt": []byte(dummy.TestCertificate1),
					},
				},
			},
			namespace:   "test-namespace",
			expectedLen: 2,
		},
		"secret with includeAllKeys should collect metrics for all keys": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{Secret: &trustapi.SourceObjectKeySelector{
							Name:           "my-secret",
							IncludeAllKeys: ptr.To(true),
						}},
					},
				},
			},
			extraObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-secret",
						Namespace: "test-namespace",
					},
					Data: map[string][]byte{
						"ca.crt":  []byte(dummy.TestCertificate1),
						"ca2.crt": []byte(dummy.TestCertificate3),
					},
				},
			},
			namespace:   "test-namespace",
			expectedLen: 4,
		},
		"configMap with key should collect metrics": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{
							Name: "my-configmap",
							Key:  "ca.crt",
						}},
					},
				},
			},
			extraObjects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-configmap",
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						"ca.crt": dummy.TestCertificate1,
					},
				},
			},
			namespace:   "test-namespace",
			expectedLen: 2,
		},
		"configMap with includeAllKeys should collect metrics for all keys": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{ConfigMap: &trustapi.SourceObjectKeySelector{
							Name:           "my-configmap",
							IncludeAllKeys: ptr.To(true),
						}},
					},
				},
			},
			extraObjects: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-configmap",
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						"ca.crt":  dummy.TestCertificate1,
						"ca2.crt": dummy.TestCertificate3,
					},
				},
			},
			namespace:   "test-namespace",
			expectedLen: 4,
		},
		"all source types combined in a single bundle should collect metrics": {
			bundle: &trustapi.Bundle{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bundle",
					Namespace: "test-namespace",
				},
				Spec: trustapi.BundleSpec{
					Sources: []trustapi.BundleSource{
						{InLine: dummy.TestCertificate1},
						{Secret: &trustapi.SourceObjectKeySelector{
							Name: "my-secret",
							Key:  "ca.crt",
						}},
						{ConfigMap: &trustapi.SourceObjectKeySelector{
							Name: "my-configmap",
							Key:  "ca.crt",
						}},
						{UseDefaultCAs: ptr.To(true)},
					},
				},
			},
			extraObjects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-secret",
						Namespace: "test-namespace",
					},
					Data: map[string][]byte{
						"ca.crt": []byte(dummy.TestCertificate3),
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "my-configmap",
						Namespace: "test-namespace",
					},
					Data: map[string]string{
						"ca.crt": dummy.TestCertificate4,
					},
				},
			},
			namespace:   "test-namespace",
			expectedLen: 8,
			defaultPackage: &fspkg.Package{
				Name:    "testpkg",
				Version: "123",
				Bundle:  dummy.TestCertificate5,
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logger := newTestLogger(t)
			scheme := runtime.NewScheme()
			require.NoError(t, trustapi.AddToScheme(scheme))
			require.NoError(t, corev1.AddToScheme(scheme))

			objects := []client.Object{tt.bundle}
			objects = append(objects, tt.extraObjects...)

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(objects...).
				Build()

			collector := NewBundleCollector(logger, controller.Options{Namespace: tt.namespace}, client, tt.defaultPackage)

			metricCh := make(chan prometheus.Metric, 100)
			collector.Collect(metricCh)
			close(metricCh)

			var metrics []prometheus.Metric
			for metric := range metricCh {
				metrics = append(metrics, metric)
			}

			require.Len(t, metrics, tt.expectedLen)
		})
	}
}

func Test_buildMetric(t *testing.T) {
	tests := map[string]struct {
		cert                   string
		bundleName             string
		kind                   string
		name                   string
		key                    string
		expectedNotAfterFirst  string
		expectedNotBeforeFirst string
	}{
		"TestCertificate1": {
			cert:                   dummy.TestCertificate1,
			bundleName:             "test-bundle",
			kind:                   "ConfigMap",
			name:                   "test-configmap",
			key:                    "cert",
			expectedNotAfterFirst:  "certmanager_ssl_ca_not_after",
			expectedNotBeforeFirst: "certmanager_ssl_ca_not_before",
		},
		"TestCertificate3": {
			cert:                   dummy.TestCertificate3,
			bundleName:             "my-bundle",
			kind:                   "Secret",
			name:                   "my-secret",
			key:                    "ca.crt",
			expectedNotAfterFirst:  "certmanager_ssl_ca_not_after",
			expectedNotBeforeFirst: "certmanager_ssl_ca_not_before",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			cert := parseTestCertificate(t, tt.cert)

			metrics := buildMetric(cert, tt.bundleName, tt.kind, tt.name, tt.key)

			require.Len(t, metrics, 2)

			assert.Equal(t, tt.expectedNotAfterFirst, getDescName(metrics[0].Desc()))
			assert.Equal(t, tt.expectedNotBeforeFirst, getDescName(metrics[1].Desc()))

			assert.Equal(t, float64(cert.NotAfter.Unix()), getMetricValue(metrics[0]))
			assert.Equal(t, float64(cert.NotBefore.Unix()), getMetricValue(metrics[1]))
		})
	}
}
