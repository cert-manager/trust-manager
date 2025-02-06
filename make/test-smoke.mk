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

# The "install" target can be run on its own with any currently active cluster,
# we can't use any other cluster then a target containing "test-smoke" is run.
# When a "test-smoke" target is run, the currently active cluster must be the kind
# cluster created by the "kind-cluster" target.
ifeq ($(findstring test-smoke,$(MAKECMDGOALS)),test-smoke)
install: kind-cluster oci-load-manager oci-load-package_debian oci-load-package_debian_bookworm
endif

test-smoke-deps: INSTALL_OPTIONS :=
test-smoke-deps: INSTALL_OPTIONS += --set image.repository=$(oci_manager_image_name_development)
test-smoke-deps: INSTALL_OPTIONS += --set defaultPackageImage.repository=$(oci_package_debian_image_name_development)
test-smoke-deps: INSTALL_OPTIONS += --set secretTargets.enabled=true --set secretTargets.authorizedSecretsAll=true
test-smoke-deps: install

.PHONY: test-smoke
## Smoke end-to-end tests
## @category Testing
test-smoke: test-smoke-deps | kind-cluster $(NEEDS_GINKGO) $(ARTIFACTS)
	$(GINKGO) \
		--output-dir=$(ARTIFACTS) \
		--junit-report=junit-go-e2e.xml \
		./test/smoke/ \
		-ldflags $(go_manager_ldflags) \
		-- \
		--kubeconfig-path $(CURDIR)/$(kind_kubeconfig)
