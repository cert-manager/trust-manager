# Copyright 2023 The cert-manager Authors.
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
FORCE:

BINDIR ?= $(CURDIR)/bin

ARCH   ?= $(shell go env GOARCH)
OS     ?= $(shell go env GOOS)

HELM_VERSION ?= 3.12.3
KUBEBUILDER_TOOLS_VERISON ?= 1.28.0
KUBECTL_VERSION ?= 1.28.2
YQ_VERSION ?= v4.40.5
KIND_VERSION ?= $(shell grep "sigs.k8s.io/kind" go.mod | awk '{print $$NF}')
GINKGO_VERSION ?= $(shell grep "github.com/onsi/ginkgo/v2" go.mod | awk '{print $$NF}')
HELM_TOOL_VERSION ?= $(shell grep "github.com/cert-manager/helm-tool" hack/tools/go.mod | awk '{print $$NF}')
BOILERSUITE_VERSION ?= $(shell grep "github.com/cert-manager/boilersuite" hack/tools/go.mod | awk '{print $$NF}')
CONTROLLER_TOOLS_VERSION ?= $(shell grep "sigs.k8s.io/controller-tools" hack/tools/go.mod | awk '{print $$NF}')
CODE_GENERATOR_VERSION ?= $(shell grep "k8s.io/code-generator" hack/tools/go.mod | awk '{print $$NF}')

IMAGE_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/ppc64le

RELEASE_VERSION ?= v0.8.0

BUILDX_BUILDER ?= trust-manager-builder

CONTAINER_REGISTRY ?= quay.io/jetstack
CONTAINER_REGISTRY_API_URL ?= https://quay.io/v2/jetstack/cert-manager-package-debian/manifests

GOPROXY ?= https://proxy.golang.org,direct

GO_SOURCES := $(shell find . -name "*.go") go.mod go.sum

CGO_ENABLED ?= 0
GOEXPERIMENT ?= # empty by default

CI ?=

# can't use a comma in an argument to a make function, so define a variable instead
_COMMA := ,

include make/color.mk
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
integration-test: | $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/kube-apiserver $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/etcd ## runs integration tests, defined as tests which require external setup (but not full end-to-end tests)
	KUBEBUILDER_ASSETS=$(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON) go test -v ./test/integration/...

.PHONY: lint
lint: vet verify-boilerplate

# Run the supplied make target argument in a temporary workspace and diff the results.
verify-%: FORCE
	./hack/util/verify.sh $(MAKE) -s $*

.PHONY: verify
verify: ## build, test and verify generate tagets
verify: depend build test
verify: verify-generate

.PHONY: verify-boilerplate
verify-boilerplate: | $(BINDIR)/boilersuite-$(BOILERSUITE_VERSION)/boilersuite
	$(BINDIR)/boilersuite-$(BOILERSUITE_VERSION)/boilersuite .

.PHONY: vet
vet:
	go vet ./...

.PHONY: build
build: $(BINDIR)/trust-manager | $(BINDIR) ## build trust-manager for the host system architecture

.PHONY: build-linux-amd64 build-linux-arm64 build-linux-ppc64le build-linux-arm
build-linux-amd64 build-linux-arm64 build-linux-ppc64le build-linux-arm: build-linux-%: $(BINDIR)/trust-manager-linux-%

$(BINDIR)/trust-manager: $(GO_SOURCES) | $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) \
		go build -o $(BINDIR)/trust-manager ./cmd/trust-manager

$(BINDIR)/trust-manager-linux-amd64 $(BINDIR)/trust-manager-linux-arm64 $(BINDIR)/trust-manager-linux-ppc64le $(BINDIR)/trust-manager-linux-arm: $(BINDIR)/trust-manager-linux-%: $(GO_SOURCES) | $(BINDIR)
	CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) \
		GOOS=linux GOARCH=$* \
		go build -o $@ ./cmd/trust-manager

.PHONY: generate
generate: depend generate-deepcopy generate-applyconfigurations generate-manifests generate-helm-docs generate-helm-schema

.PHONY: generate-deepcopy
generate-deepcopy: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
generate-deepcopy: | $(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)/controller-gen
	$(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)/controller-gen object:headerFile="hack/boilerplate/boilerplate.go.txt" paths="./..."

GO_MODULE := $(shell go list -m)
API_DIRS := $(shell find pkg/apis -mindepth 2 -type d | sed "s|^|$(GO_MODULE)/|" | paste -sd "," -)

.PHONY: generate-applyconfigurations
generate-applyconfigurations: ## Generate applyconfigurations to support typesafe SSA.
generate-applyconfigurations: | $(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION)/applyconfiguration-gen
	rm -rf pkg/applyconfigurations
	@echo ">> generating pkg/applyconfigurations..."
	$(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION)/applyconfiguration-gen \
		--go-header-file 	hack/boilerplate/boilerplate.go.txt \
		--input-dirs		"$(API_DIRS)" \
		--output-package  	"$(GO_MODULE)/pkg/applyconfigurations" \
		--trim-path-prefix 	"$(GO_MODULE)" \
		--output-base    	"."

.PHONY: generate-manifests
generate-manifests: ## Generate CustomResourceDefinition objects.
generate-manifests: $(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)/controller-gen $(BINDIR)/yq-$(YQ_VERSION)/yq
	./hack/update-codegen.sh $^

# See wait-for-buildx.sh for an explanation of why it's needed
.PHONY: provision-buildx
provision-buildx:  ## set up docker buildx for multiarch building; required for building images
ifeq ($(OS), linux)
	# This step doesn't work on macOS and doesn't seem to be required (at least with docker desktop)
	# It did seem to be needed in Linux, at least in certain configurations when running on amd64
	# TODO: it might be preferable to move away from docker buildx in the long term to avoid the dependency on Docker
	docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
endif
	docker buildx rm $(BUILDX_BUILDER) &>/dev/null || :
	./hack/wait-for-buildx.sh $(BUILDX_BUILDER) gone
	docker buildx create --name $(BUILDX_BUILDER) --bootstrap --driver docker-container --platform $(IMAGE_PLATFORMS)
	./hack/wait-for-buildx.sh $(BUILDX_BUILDER) exists
	docker buildx inspect --bootstrap --builder $(BUILDX_BUILDER)

.PHONY: image
image: trust-manager-save | $(BINDIR) ## build trust-manager container images targeting all supported platforms and save to disk. Requires `make provision-buildx`

.PHONY: local-images
local-images: trust-manager-load trust-package-debian-load  ## build container images for only the local architecture and load into docker. Requires `make provision-buildx`

.PHONY: kind-load
kind-load: local-images | $(BINDIR)/kind-$(KIND_VERSION)/kind  ## same as local-images but also run "kind load docker-image"
	$(BINDIR)/kind-$(KIND_VERSION)/kind load docker-image \
		--name trust \
		$(CONTAINER_REGISTRY)/trust-manager:latest \
		$(CONTAINER_REGISTRY)/cert-manager-package-debian:latest$(DEBIAN_TRUST_PACKAGE_SUFFIX)

.PHONY: chart
chart: | $(BINDIR)/helm-$(HELM_VERSION)/helm $(BINDIR)/chart
	$(BINDIR)/helm-$(HELM_VERSION)/helm package --app-version=$(RELEASE_VERSION) --version=$(RELEASE_VERSION) --destination "$(BINDIR)/chart" ./deploy/charts/trust-manager

.PHONY: generate-helm-docs
generate-helm-docs: | $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool  ## update Helm README, generated from other Helm files
	./hack/update-helm-tool.sh $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool

.PHONY: generate-helm-schema
generate-helm-schema: | $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool  ## update Helm README, generated from other Helm files
	$(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool schema -i ./deploy/charts/trust-manager/values.yaml | jq > ./deploy/charts/trust-manager/values.schema.json

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

.PHONY: demo
demo: ensure-kind kind-load ensure-cert-manager ensure-trust-manager $(BINDIR)/kubeconfig.yaml  ## ensure a cluster ready for a smoke test or local testing

.PHONY: smoke
smoke: demo | $(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo  ## ensure local cluster exists, deploy trust-manager and run smoke tests
	$(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo -procs 1 test/smoke/ -- --kubeconfig-path $(BINDIR)/kubeconfig.yaml

$(BINDIR)/kubeconfig.yaml: ensure-ci-docker-network _FORCE test/kind-cluster.yaml | $(BINDIR)/kind-$(KIND_VERSION)/kind
	@if $(BINDIR)/kind-$(KIND_VERSION)/kind get clusters | grep -q "^trust$$"; then \
		echo "cluster already exists, not trying to create"; \
		$(BINDIR)/kind-$(KIND_VERSION)/kind get kubeconfig --name trust > $@ && chmod 600 $@; \
	else \
		$(BINDIR)/kind-$(KIND_VERSION)/kind create cluster --config test/kind-cluster.yaml --kubeconfig $@ && chmod 600 $@; \
		echo -e "$(_RED)kind cluster 'trust' was created; to access it, pass '--kubeconfig  $(BINDIR)/kubeconfig.yaml' to kubectl/helm$(_END)"; \
		sleep 2; \
	fi

.PHONY: ensure-kind
ensure-kind: $(BINDIR)/kubeconfig.yaml  ## create a trust-manager kind cluster, if one doesn't already exist

.PHONY: ensure-cert-manager
ensure-cert-manager: ensure-kind $(BINDIR)/kubeconfig.yaml | $(BINDIR)/helm-$(HELM_VERSION)/helm  ## ensure cert-manager is installed on cluster for testing
	@if $(BINDIR)/helm-$(HELM_VERSION)/helm --kubeconfig $(BINDIR)/kubeconfig.yaml list --short --namespace cert-manager --selector name=cert-manager | grep -q cert-manager; then \
		echo "cert-manager already installed, not trying to reinstall"; \
	else \
		$(BINDIR)/helm-$(HELM_VERSION)/helm repo add jetstack https://charts.jetstack.io --force-update; \
		$(BINDIR)/helm-$(HELM_VERSION)/helm upgrade --kubeconfig $(BINDIR)/kubeconfig.yaml -i --create-namespace -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait; \
	fi

.PHONY: ensure-trust-manager
ensure-trust-manager: ensure-kind kind-load ensure-cert-manager | $(BINDIR)/helm-$(HELM_VERSION)/helm  ## ensure trust-manager is available on cluster, built from local checkout
	$(BINDIR)/helm-$(HELM_VERSION)/helm uninstall --kubeconfig $(BINDIR)/kubeconfig.yaml -n cert-manager trust-manager || :
	$(BINDIR)/helm-$(HELM_VERSION)/helm upgrade --kubeconfig $(BINDIR)/kubeconfig.yaml -i -n cert-manager trust-manager deploy/charts/trust-manager/. \
		--set image.tag=latest \
		--set defaultPackageImage.tag=latest$(DEBIAN_TRUST_PACKAGE_SUFFIX) \
		--set app.logLevel=2 \
		--set secretTargets.enabled=true --set secretTargets.authorizedSecretsAll=true \
		--wait

# When running in our CI environment the Docker network's subnet choice
# causees issues with routing.
# Creating a custom kind network gets around that problem.
.PHONY: ensure-ci-docker-network
ensure-ci-docker-network:
ifneq ($(strip $(CI)),)
	@echo -e "$(_RED)Creating CI docker network$(_END); this will cause problems if you're not in CI"
	@echo "To undo, run 'docker network rm kind'"
	@sleep 2
	docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
	@# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
	@sleep 2
endif

.PHONY: build-validate-trust-package
build-validate-trust-package: $(BINDIR)/validate-trust-package

$(BINDIR)/validate-trust-package: cmd/validate-trust-package/main.go pkg/fspkg/package.go | $(BINDIR)
	CGO_ENABLED=0 go build -o $@ $<

.PHONY: depend
depend: $(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)/controller-gen
depend: $(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION)/applyconfiguration-gen
depend: $(BINDIR)/boilersuite-$(BOILERSUITE_VERSION)/boilersuite
depend: $(BINDIR)/kind-$(KIND_VERSION)/kind
depend: $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool
depend: $(BINDIR)/helm-$(HELM_VERSION)/helm
depend: $(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo
depend: $(BINDIR)/kubectl-$(KUBECTL_VERSION)/kubectl
depend: $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/kube-apiserver
depend: $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/etcd
depend: $(BINDIR)/yq-$(YQ_VERSION)/yq

$(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)/controller-gen: | $(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION)
	cd hack/tools && go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION)/applyconfiguration-gen: | $(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION)
	cd hack/tools && go build -o $@ k8s.io/code-generator/cmd/applyconfiguration-gen

$(BINDIR)/boilersuite-$(BOILERSUITE_VERSION)/boilersuite: | $(BINDIR)/boilersuite-$(BOILERSUITE_VERSION)
	cd hack/tools && go build -o $@ github.com/cert-manager/boilersuite

$(BINDIR)/kind-$(KIND_VERSION)/kind: | $(BINDIR)/kind-$(KIND_VERSION)
	cd hack/tools && go build -o $@ sigs.k8s.io/kind

$(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)/helm-tool: | $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION)
	cd hack/tools && go build -o $@ github.com/cert-manager/helm-tool

$(BINDIR)/helm-$(HELM_VERSION)/helm: $(BINDIR)/helm-$(HELM_VERSION)/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz | $(BINDIR)
	tar xfO $< $(OS)-$(ARCH)/helm > $@ && chmod +x $@

$(BINDIR)/helm-$(HELM_VERSION)/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz: | $(BINDIR)/helm-$(HELM_VERSION)
	curl -o $@ -LO "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"

$(BINDIR)/ginkgo-$(GINKGO_VERSION)/ginkgo: | $(BINDIR)
	GOBIN=$(dir $@) go install github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VERSION)

$(BINDIR)/kubectl-$(KUBECTL_VERSION)/kubectl: | $(BINDIR)/kubectl-$(KUBECTL_VERSION)
	curl -o $@ -L "https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/$(OS)/$(ARCH)/kubectl" && chmod +x $@

$(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/etcd: $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/envtest-bins.tar.gz | $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod +x $@

$(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/kube-apiserver: $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/envtest-bins.tar.gz | $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod +x $@

$(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)/envtest-bins.tar.gz: | $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON)
	curl -sSL -o $@ "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_TOOLS_VERISON)-$(OS)-$(ARCH).tar.gz"

$(BINDIR)/yq-$(YQ_VERSION)/yq: | $(BINDIR)/yq-$(YQ_VERSION)
	curl -o $@ -L "https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(OS)_$(ARCH)" && chmod +x $@

$(BINDIR) $(BINDIR)/kubectl-$(KUBECTL_VERSION) $(BINDIR)/kubebuilder-$(KUBEBUILDER_TOOLS_VERISON) $(BINDIR)/chart $(BINDIR)/ginkgo-$(GINKGO_VERSION) $(BINDIR)/helm-$(HELM_VERSION) $(BINDIR)/helm-tool-$(HELM_TOOL_VERSION) $(BINDIR)/kind-$(KIND_VERSION) $(BINDIR)/boilersuite-$(BOILERSUITE_VERSION) $(BINDIR)/controller-tools-$(CONTROLLER_TOOLS_VERSION) $(BINDIR)/code-generator-$(CODE_GENERATOR_VERSION) $(BINDIR)/yq-$(YQ_VERSION):
	@mkdir -p $@

_FORCE:
