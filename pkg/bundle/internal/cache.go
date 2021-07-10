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

package internal

import (
	"context"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ cache.Cache = &MultiScopedCache{}

// TODO
type MultiScopedCache struct {
	namespacedCache cache.Cache
	clusterCache    cache.Cache

	namespacedInformers []schema.GroupKind
}

func NewMultiScopedCache(namespace string, namespacedInformers []schema.GroupKind) cache.NewCacheFunc {
	return func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
		namespacedCache, err := cache.MultiNamespacedCacheBuilder([]string{namespace})(config, opts)
		if err != nil {
			return nil, err
		}
		clusterCache, err := cache.New(config, opts)
		if err != nil {
			return nil, err
		}
		return &MultiScopedCache{
			namespacedCache:     namespacedCache,
			clusterCache:        clusterCache,
			namespacedInformers: namespacedInformers,
		}, nil
	}
}

// TODO
func (b *MultiScopedCache) GetInformer(ctx context.Context, obj client.Object) (cache.Informer, error) {
	return b.cacheFromGVK(obj.GetObjectKind().GroupVersionKind()).GetInformer(ctx, obj)
}

// TODO
func (b *MultiScopedCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind) (cache.Informer, error) {
	return b.cacheFromGVK(gvk).GetInformerForKind(ctx, gvk)
}

// TODO
func (b *MultiScopedCache) Start(ctx context.Context) error {
	var (
		errs []error
		lock sync.Mutex
		wg   sync.WaitGroup
	)

	for _, c := range []cache.Cache{b.namespacedCache, b.clusterCache} {
		wg.Add(1)
		go func(c cache.Cache) {
			if err := c.Start(ctx); err != nil {
				lock.Lock()
				defer lock.Unlock()
				errs = append(errs, err)
			}

			wg.Done()
		}(c)
	}

	wg.Wait()

	return utilerrors.NewAggregate(errs)
}

// TODO
func (b *MultiScopedCache) WaitForCacheSync(ctx context.Context) bool {
	for _, c := range []cache.Cache{b.namespacedCache, b.clusterCache} {
		if !c.WaitForCacheSync(ctx) {
			return false
		}
	}
	return true
}

// TODO
func (b *MultiScopedCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	return b.cacheFromGVK(obj.GetObjectKind().GroupVersionKind()).IndexField(ctx, obj, field, extractValue)
}

// TODO
func (b *MultiScopedCache) Get(ctx context.Context, key client.ObjectKey, obj client.Object) error {
	return b.cacheFromGVK(obj.GetObjectKind().GroupVersionKind()).Get(ctx, key, obj)
}

// TODO
func (b *MultiScopedCache) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return b.cacheFromGVK(list.GetObjectKind().GroupVersionKind()).List(ctx, list, opts...)
}

// TODO
func (b *MultiScopedCache) cacheFromGVK(gvk schema.GroupVersionKind) cache.Cache {
	for _, namespacedInformer := range b.namespacedInformers {
		if namespacedInformer.Group == gvk.Group && namespacedInformer.Kind == gvk.Kind {
			return b.namespacedCache
		}
	}
	return b.clusterCache
}
