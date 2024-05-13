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

trust_manager_crds := $(bin_dir)/scratch/trust.cert-manager.io_bundles.yaml
$(trust_manager_crds): $(helm_chart_archive) | $(NEEDS_HELM) $(NEEDS_YQ)
	$(HELM) template test "$(helm_chart_archive)" | \
		$(YQ) e '. | select(.kind == "CustomResourceDefinition")' \
		> $@

.PHONY: test-integration
## Integration tests
## @category Testing
test-integration: | $(trust_manager_crds) $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBE-APISERVER) $(NEEDS_KUBECTL) $(ARTIFACTS)
	TRUST_MANAGER_CRDS=$(CURDIR)/$(trust_manager_crds) \
	KUBEBUILDER_ASSETS=$(CURDIR)/$(bin_dir)/tools \
	$(GOTESTSUM) \
		--junitfile=$(ARTIFACTS)/junit-go-e2e.xml \
		-- \
		-coverprofile=$(ARTIFACTS)/filtered.cov \
		./test/integration/... \
		-- \
		-ldflags $(go_manager_ldflags) \
		-test.timeout 2m
