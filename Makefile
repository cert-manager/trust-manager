# Copyright 2022 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:

BINDIR ?= $(CURDIR)/bin

ARCH   ?= $(shell go env GOARCH)
OS     ?= $(shell go env GOOS)

HELM_VERSION ?= 3.10.3
KUBEBUILDER_TOOLS_VERISON ?= 1.25.0
GINKGO_VERSION ?= $(shell grep "github.com/onsi/ginkgo/v2" go.mod | awk '{print $$NF}')
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le

RELEASE_VERSION ?= v0.3.0

BUILDX_BUILDER ?= trust-manager-builder

CONTAINER_REGISTRY ?= quay.io/jetstack

GOPROXY ?= https://proxy.golang.org,direct

CI ?=

# can't use a comma in an argument to a make function, so define a variable instead
_COMMA := ,

include make/trust-manager-build.mk
include make/trust-package-debian.mk

.PHONY: help
help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: all
all: depend generate test build image ## runs test, build and image

.PHONY: test
test: lint unit-test integration-test ## test trust-manager, running linters, unit and integration tests

.PHONY: unit-test
unit-test:  ## runs unit tests, defined as any test which doesn't require external stup
	go test -v ./pkg/... ./cmd/...

.PHONY: integration-test
integration-test: depend  ## runs integration tests, defined as tests which require external setup (but not full end-to-end tests)
	KUBEBUILDER_ASSETS=$(BINDIR)/kubebuilder/bin go test -v ./test/integration/...

.PHONY: lint
lint: vet verify-boilerplate verify-helm-docs

.PHONY: verify
verify: depend build test ## tests and builds trust-manager

.PHONY: verify-boilerplate
verify-boilerplate:
	./hack/verify-boilerplate.sh

.PHONY: vet
vet:
	go vet ./...

.PHONY: build
build: | $(BINDIR) ## build trust
	CGO_ENABLED=0 go build -o $(BINDIR)/trust-manager ./cmd/.

.PHONY: generate
generate: depend ## generate code
	./hack/update-codegen.sh

# See wait-for-buildx.sh for an explanation of why it's needed
.PHONY: provision-buildx
provision-buildx:  ## set up docker buildx for multiarch building
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
	docker buildx rm $(BUILDX_BUILDER) &>/dev/null || :
	./hack/wait-for-buildx.sh $(BUILDX_BUILDER) gone
	docker buildx create --name $(BUILDX_BUILDER) --driver docker-container --use
	./hack/wait-for-buildx.sh $(BUILDX_BUILDER) exists
	docker buildx inspect --bootstrap --builder $(BUILDX_BUILDER)

.PHONY: image
image: trust-manager-save trust-package-debian-save | $(BINDIR) ## build docker images targeting all supported platforms and save to disk

.PHONY: local-images
local-images: trust-manager-load trust-package-debian-load  ## build container images for only amd64 and load into docker

.PHONY: kind-load
kind-load: local-images | $(BINDIR)/kind  ## same as local-images but also run "kind load docker-image"
	$(BINDIR)/kind load docker-image \
		--name trust \
		$(CONTAINER_REGISTRY)/trust-manager:latest \
		$(CONTAINER_REGISTRY)/cert-manager-package-debian:latest$(DEBIAN_TRUST_PACKAGE_SUFFIX)

.PHONY: chart
chart: | $(BINDIR)/helm $(BINDIR)/chart
	$(BINDIR)/helm package --app-version=$(RELEASE_VERSION) --version=$(RELEASE_VERSION) --destination "$(BINDIR)/chart" ./deploy/charts/trust-manager

.PHONY: verify-helm-docs
verify-helm-docs: | $(BINDIR)/helm-docs
	./hack/verify-helm-docs.sh $(BINDIR)/helm-docs

.PHONY: update-helm-docs
update-helm-docs: | $(BINDIR)/helm-docs  ## update Helm README, generated from other Helm files
	./hack/update-helm-docs.sh $(BINDIR)/helm-docs

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

.PHONY: demo
demo: ensure-kind kind-load ensure-cert-manager ensure-trust-manager $(BINDIR)/kubeconfig.yaml  ## ensure a cluster ready for a smoke test or local testing

.PHONY: smoke
smoke: demo  ## ensure local cluster exists, deploy trust-manager and run smoke tests
	$(BINDIR)/ginkgo -procs 1 test/smoke/ -- --kubeconfig-path $(BINDIR)/kubeconfig.yaml

$(BINDIR)/kubeconfig.yaml: depend ensure-ci-docker-network _FORCE | $(BINDIR)
	@if $(BINDIR)/kind get clusters | grep -q "^trust$$"; then \
		echo "cluster already exists, not trying to create"; \
		$(BINDIR)/kind get kubeconfig --name trust > $@ && chmod 600 $@; \
	else \
		$(BINDIR)/kind create cluster --name trust --kubeconfig $@ && chmod 600 $@; \
	fi

.PHONY: ensure-kind
ensure-kind: $(BINDIR)/kubeconfig.yaml  ## create a trust-manager kind cluster, if one doesn't already exist

.PHONY: ensure-cert-manager
ensure-cert-manager: depend ensure-kind $(BINDIR)/kubeconfig.yaml  ## ensure cert-manager is installed on cluster for testing
	@if $(BINDIR)/helm --kubeconfig $(BINDIR)/kubeconfig.yaml list --short --namespace cert-manager --selector name=cert-manager | grep -q cert-manager; then \
		echo "cert-manager already installed, not trying to reinstall"; \
	else \
		$(BINDIR)/helm repo add jetstack https://charts.jetstack.io --force-update; \
		$(BINDIR)/helm upgrade --kubeconfig $(BINDIR)/kubeconfig.yaml -i --create-namespace -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait; \
	fi

.PHONY: ensure-trust-manager
ensure-trust-manager: depend ensure-kind kind-load ensure-cert-manager  ## ensure trust-manager is available on cluster, built from local checkout
	$(BINDIR)/helm uninstall --kubeconfig $(BINDIR)/kubeconfig.yaml -n cert-manager trust-manager || :
	$(BINDIR)/helm upgrade --kubeconfig $(BINDIR)/kubeconfig.yaml -i -n cert-manager trust-manager deploy/charts/trust-manager/. --set image.tag=latest --set defaultTrustPackage.tag=latest$(DEBIAN_TRUST_PACKAGE_SUFFIX) --set app.logLevel=2 --wait

# When running in our CI environment the Docker network's subnet choice
# causees issues with routing.
# Creating a custom kind network gets around that problem.
.PHONY: ensure-ci-docker-network
ensure-ci-docker-network:
ifneq ($(strip $(CI)),)
	docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
	@# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
	sleep 2
endif

.PHONY: build-validate-trust-package
build-validate-trust-package: $(BINDIR)/validate-trust-package

$(BINDIR)/validate-trust-package: cmd/validate-trust-package/main.go pkg/fspkg/package.go | $(BINDIR)
	CGO_ENABLED=0 go build -o $@ $<

.PHONY: depend
depend: $(BINDIR)/deepcopy-gen $(BINDIR)/controller-gen $(BINDIR)/ginkgo $(BINDIR)/kubectl $(BINDIR)/kind $(BINDIR)/helm $(BINDIR)/kubebuilder/bin/kube-apiserver

$(BINDIR)/deepcopy-gen: | $(BINDIR)
	go build -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(BINDIR)/controller-gen: | $(BINDIR)
	go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(BINDIR)/ginkgo: $(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo
	cp -f $< $@

$(BINDIR)/ginkgo-$(GINKGO_VERSION): | $(BINDIR)
	mkdir -p $@

$(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo: | $(BINDIR)
	GOBIN=$(dir $@) go install github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VERSION)

$(BINDIR)/kind: | $(BINDIR)
	go build -o $(BINDIR)/kind sigs.k8s.io/kind

$(BINDIR)/helm: $(BINDIR)/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz | $(BINDIR)
	tar xfO $< $(OS)-$(ARCH)/helm > $@
	chmod +x $@

$(BINDIR)/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz: | $(BINDIR)
	curl -o $@ -LO "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"

$(BINDIR)/helm-docs: | $(BINDIR)
	cd hack/tools && go build -o $@ github.com/norwoodj/helm-docs/cmd/helm-docs

$(BINDIR)/kubectl: | $(BINDIR)
	curl -o $@ -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x $@

$(BINDIR)/kubebuilder/bin/kube-apiserver: | $(BINDIR)/kubebuilder
	curl -sSLo $(BINDIR)/envtest-bins.tar.gz "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_TOOLS_VERISON)-$(OS)-$(ARCH).tar.gz"
	tar -C $(BINDIR)/kubebuilder --strip-components=1 -zvxf $(BINDIR)/envtest-bins.tar.gz

$(BINDIR) $(BINDIR)/kubebuilder $(BINDIR)/chart:
	@mkdir -p $@

_FORCE:
