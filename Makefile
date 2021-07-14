# Copyright 2021 The cert-manager Authors.
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

BINDIR ?= $(CURDIR)/bin
ARCH   ?= amd64

.PHONY: deploy

help:  ## display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: all
all: test build image ## runs test, build and image

.PHONY: test
test: generate lint ## test trust
	go test -v ./...

.PHONY: test
lint:
	./hack/verify-boilerplate.sh

.PHONY: build
build: generate ## build trust
	mkdir -p $(BINDIR)
	CGO_ENABLED=0 go build -o ./bin/cert-manager-trust ./cmd/.

.PHONY: generate
generate: depend ## generate code
	./hack/update-codegen.sh

.PHONY: verify
verify: test build ## tests and builds trust

.PHONY: image
image: ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/cert-manager-trust-linux ./cmd/.
	docker build -t quay.io/jetstack/cert-manager-trust:v0.0.1 .

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR)

.PHONY: push_image
push_image: image
	docker push localhost:5000/cert-manager/trust:v0.0.1

.PHONY: cluster
cluster: ## create kind cluster with local registry
	./hack/create-cluster.sh

.PHONY: deploy
deploy: ## deploy trust manifests
	kubectl apply -f ./deploy/crds
	kubectl apply -f ./deploy/yaml

.PHONY: demo
demo: all cluster push_image deploy ## create cluster and deploy trust with demo

.PHONY: depend
depend: $(BINDIR)/deepcopy-gen $(BINDIR)/controller-gen

$(BINDIR)/deepcopy-gen:
	mkdir -p $(BINDIR)
	go build -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(BINDIR)/controller-gen:
	mkdir -p $(BINDIR)
	go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen
