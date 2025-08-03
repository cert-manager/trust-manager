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

package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"path"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	trustmanagerapi "github.com/cert-manager/trust-manager/pkg/apis/trustmanager/v1alpha2"
	"github.com/cert-manager/trust-manager/pkg/webhook"
	"github.com/cert-manager/trust-manager/test"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	env *envtest.Environment
)

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	env = &envtest.Environment{
		UseExistingCluster: ptr.To(false),
		CRDDirectoryPaths: []string{
			path.Join("..", "..", "..", "deploy", "crds"),
		},
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			ValidatingWebhooks: []*admissionv1.ValidatingWebhookConfiguration{validatingWebhookConfiguration()},
		},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := env.Start()
	Expect(err).NotTo(HaveOccurred())
	if err != nil {
		env = nil // prevent AfterSuite from trying to stop it
	}

	// start webhook server using Manager
	webhookInstallOptions := &env.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: test.Scheme,
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			Host:    webhookInstallOptions.LocalServingHost,
			Port:    webhookInstallOptions.LocalServingPort,
			CertDir: webhookInstallOptions.LocalServingCertDir,
		}),
		LeaderElection: false,
		Metrics:        server.Options{BindAddress: "0"},
	})
	Expect(err).NotTo(HaveOccurred())

	Expect(webhook.SetupWebhookWithManager(mgr)).Should(Succeed())
	Expect((&webhook.ClusterBundle{}).SetupWebhookWithManager(mgr)).Should(Succeed())

	go func() {
		defer GinkgoRecover()
		err = mgr.Start(context.TODO())
		Expect(err).NotTo(HaveOccurred())
	}()

	// wait for the webhook server to get ready
	dialer := &net.Dialer{Timeout: time.Second}
	addrPort := fmt.Sprintf("%s:%d", webhookInstallOptions.LocalServingHost, webhookInstallOptions.LocalServingPort)
	Eventually(func() error {
		conn, err := tls.DialWithDialer(dialer, "tcp", addrPort, &tls.Config{InsecureSkipVerify: true}) // #nosec G402
		if err != nil {
			return err
		}
		return conn.Close()
	}).Should(Succeed())
})

// validatingWebhookConfiguration creates a simplified validating webhook configuration.
// We should ideally use the "real" configuration, but it's currently sourced from a Helm template only,
// which is not supported by envtest.
func validatingWebhookConfiguration() *admissionv1.ValidatingWebhookConfiguration {
	v := &admissionv1.ValidatingWebhookConfiguration{}
	v.Name = "trust-manager"
	v.Webhooks = []admissionv1.ValidatingWebhook{
		bundleValidatingWebhook(),
		clusterBundleValidatingWebhook(),
	}
	return v
}

func bundleValidatingWebhook() admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name: "trust.cert-manager.io",
		Rules: []admissionv1.RuleWithOperations{{
			Rule: admissionv1.Rule{
				APIGroups:   []string{trustapi.SchemeGroupVersion.Group},
				APIVersions: []string{"v1alpha1"},
				Resources:   []string{"bundles"},
			},
			Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
		}},
		SideEffects:             ptr.To(admissionv1.SideEffectClassNone),
		AdmissionReviewVersions: []string{"v1"},
		ClientConfig: admissionv1.WebhookClientConfig{
			Service: &admissionv1.ServiceReference{
				Namespace: "cert-manager",
				Name:      "trust-manager",
				Path:      ptr.To("/validate-trust-cert-manager-io-v1alpha1-bundle"),
			},
		},
	}
}

func clusterBundleValidatingWebhook() admissionv1.ValidatingWebhook {
	return admissionv1.ValidatingWebhook{
		Name: "v1alpha2-clusterbundles-validator.trust-manager.io",
		Rules: []admissionv1.RuleWithOperations{{
			Rule: admissionv1.Rule{
				APIGroups:   []string{trustmanagerapi.SchemeGroupVersion.Group},
				APIVersions: []string{"v1alpha2"},
				Resources:   []string{"clusterbundles"},
			},
			Operations: []admissionv1.OperationType{admissionv1.Create, admissionv1.Update},
		}},
		SideEffects:             ptr.To(admissionv1.SideEffectClassNone),
		AdmissionReviewVersions: []string{"v1"},
		ClientConfig: admissionv1.WebhookClientConfig{
			Service: &admissionv1.ServiceReference{
				Namespace: "cert-manager",
				Name:      "trust-manager",
				Path:      ptr.To("/validate-trust-manager-io-v1alpha2-clusterbundle"),
			},
		},
	}
}

var _ = AfterSuite(func() {
	if env == nil {
		Expect(env.Stop()).NotTo(HaveOccurred())
	}
})
