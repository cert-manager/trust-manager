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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	multiscopedcache "github.com/cert-manager/trust-manager/pkg/bundle/cache"
)

var _ = Describe("Integration test cache", func() {
	It("should be possible to Get a resource without having cluster-wide List & Watch permissions", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		namespace := "test-namespace"

		// Create a service account that can only retrieve secrets in a single namespace.
		var cacheRestConfig *rest.Config
		{
			godClient, err := client.New(env.Config, client.Options{})
			Expect(err).NotTo(HaveOccurred())

			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			err = godClient.Create(ctx, ns)
			Expect(err).NotTo(HaveOccurred())

			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-sa",
					Namespace: namespace,
				},
			}
			err = godClient.Create(ctx, sa)
			Expect(err).NotTo(HaveOccurred())

			role := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-role",
					Namespace: namespace,
				},
				Rules: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"list", "watch"},
						APIGroups: []string{""},
						Resources: []string{"secrets"},
					},
				},
			}
			err = godClient.Create(ctx, role)
			Expect(err).NotTo(HaveOccurred())

			rolebinding := rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cache-rolebinding",
					Namespace: namespace,
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "cache-role",
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "cache-sa",
						Namespace: namespace,
					},
				},
			}
			err = godClient.Create(ctx, &rolebinding)
			Expect(err).NotTo(HaveOccurred())

			// Create a config that uses the service account.
			cacheRestConfig = rest.CopyConfig(env.Config)
			cacheRestConfig.Impersonate.UserName = fmt.Sprintf("system:serviceaccount:%s:%s", namespace, "cache-sa")
			cacheRestConfig.Impersonate.UID = string(sa.UID)

			// Create a secret that the service account can access.
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					"test": []byte("test"),
				},
			}
			err = godClient.Create(ctx, secret)
			Expect(err).NotTo(HaveOccurred())
		}

		newCache := multiscopedcache.NewMultiScopedCache(namespace, []schema.GroupKind{{Group: "", Kind: "Secret"}})

		scheme := runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		cache, err := newCache(cacheRestConfig, cache.Options{
			Scheme: scheme,
		})
		Expect(err).NotTo(HaveOccurred())

		done := make(chan error)
		go func() {
			done <- cache.Start(ctx)
		}()
		defer func() {
			Expect(<-done).NotTo(HaveOccurred())
		}()

		Expect(cache.WaitForCacheSync(ctx)).To(BeTrue())

		secret := &corev1.Secret{}
		err = cache.Get(ctx, client.ObjectKey{
			Namespace: namespace,
			Name:      "test-secret",
		}, secret)
		Expect(err).NotTo(HaveOccurred())

		Expect(secret.Data["test"]).To(Equal([]byte("test")))
	})
})
