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

package inject

import (
	"context"
	"path"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/controller"
	"github.com/cert-manager/trust-manager/pkg/bundle/inject"
	"github.com/cert-manager/trust-manager/test/dummy"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const bundleName = "my-bundle"

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
	ctx       context.Context
	cancel    context.CancelFunc
)

func TestAPIs(t *testing.T) {
	ctx = t.Context()
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	_, cancel = context.WithCancel(ctx)

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		UseExistingCluster: ptr.To(false),
		CRDDirectoryPaths: []string{
			path.Join("..", "..", "..", "..", "deploy", "crds"),
		},
		ErrorIfCRDPathMissing: true,
		Scheme:                trustapi.GlobalScheme,
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: trustapi.GlobalScheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
	komega.SetClient(k8sClient)

	setupBundle()

	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Client: client.Options{Cache: &client.CacheOptions{Unstructured: true}},
		Scheme: trustapi.GlobalScheme,
		Metrics: server.Options{
			// Disable metrics server to avoid port conflict
			BindAddress: "0",
		},
	})
	Expect(err).NotTo(HaveOccurred())

	injector := &inject.Injector{
		Client: k8sManager.GetClient(),
	}
	Expect(injector.SetupWithManager(k8sManager, controller.Options{})).To(Succeed())
	cleaner := &inject.Cleaner{
		Client: k8sManager.GetClient(),
	}
	Expect(cleaner.SetupWithManager(k8sManager)).To(Succeed())

	go func() {
		defer GinkgoRecover()
		var ctrlCtx context.Context
		ctrlCtx, cancel = context.WithCancel(ctrl.SetupSignalHandler())
		Expect(k8sManager.Start(ctrlCtx)).To(Succeed())
	}()
})

var _ = AfterSuite(func() {
	cancel()

	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

func setupBundle() {
	bundle := &trustapi.Bundle{}
	bundle.Name = bundleName
	bundle.Spec.Sources = []trustapi.BundleSource{{
		InLine: ptr.To(dummy.TestCertificate1),
	}}

	err := k8sClient.Create(ctx, bundle)
	Expect(err).NotTo(HaveOccurred())
}
