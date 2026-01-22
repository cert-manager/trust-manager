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

$(kind_cluster_config): make/config/kind/cluster.yaml | $(bin_dir)/scratch
	cat $< | \
	sed -e 's|{{KIND_IMAGES}}|$(CURDIR)/$(images_tar_dir)|g' \
	> $@

include make/test-smoke.mk
include make/test-integration.mk
include make/test-unit.mk

# Deprecated ci-target for backwards compatibility
.PHONY: provision-buildx
provision-buildx: noop

# Deprecated ci-target for backwards compatibility
.PHONY: smoke
smoke:
	$(MAKE) test-unit
	$(MAKE) test-integration
	$(MAKE) test-smoke

include make/validate-trust-package.mk
include make/debian-bullseye-trust-package.mk
include make/debian-bookworm-trust-package.mk

.PHONY: prerelease-scan
## Perform security scans on the codebase with govulncheck and on released trust packages
## using Trivy. This is intended as a signal for whether a release is safe to proceed.
## @category [shared] Release
prerelease-scan: verify-govulncheck scan-debian-bookworm-trust-package scan-debian-bullseye-trust-package | $(NEEDS_TRIVY) $(NEEDS_CRANE)

.PHONY: release
## Publish all release artifacts (image + helm chart)
## @category [shared] Release
release:
	$(MAKE) oci-push-manager
	$(MAKE) helm-chart-oci-push
	$(MAKE) oci-maybe-push-package_debian_bullseye
	$(MAKE) oci-maybe-push-package_debian_bookworm

	@echo "RELEASE_OCI_MANAGER_IMAGE=$(oci_manager_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_MANAGER_TAG=$(oci_manager_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BULLSEYE_IMAGE=$(oci_package_debian_bullseye_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BULLSEYE_TAG=$(oci_package_debian_bullseye_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BOOKWORM_IMAGE=$(oci_package_debian_bookworm_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BOOKWORM_TAG=$(oci_package_debian_bookworm_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_HELM_CHART_IMAGE=$(helm_chart_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_HELM_CHART_VERSION=$(helm_chart_version)" >> "$(GITHUB_OUTPUT)"

	@echo "Release complete!"

.PHONY: release-debian-bullseye-trust-package
release-debian-bullseye-trust-package:
	$(MAKE) oci-maybe-push-package_debian_bullseye

	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BULLSEYE_IMAGE=$(oci_package_debian_bullseye_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BULLSEYE_TAG=$(oci_package_debian_bullseye_image_tag)" >> "$(GITHUB_OUTPUT)"

	@echo "Release complete!"

.PHONY: release-debian-bookworm-trust-package
release-debian-bookworm-trust-package: | $(NEEDS_CRANE)
	$(MAKE) oci-maybe-push-package_debian_bookworm

	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BOOKWORM_IMAGE=$(oci_package_debian_bookworm_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_PACKAGE_DEBIAN_BOOKWORM_TAG=$(oci_package_debian_bookworm_image_tag)" >> "$(GITHUB_OUTPUT)"

	@echo "Release complete!"

.PHONY: generate-applyconfigurations
## Generate applyconfigurations to support typesafe SSA.
## @category Generate/ Verify
generate-applyconfigurations: | $(NEEDS_CONTROLLER-GEN)
	$(eval directories := $(shell ls -d */ | grep -v '_bin' | grep -v 'make'))
	$(CONTROLLER-GEN) applyconfiguration:headerFile=$(go_header_file) $(directories:%=paths=./%...)

shared_generate_targets += generate-applyconfigurations

.PHONY: generate-conversion
## Generate code for converting between Bundle and ClusterBundle API
## @category Generate/ Verify
generate-conversion: | $(NEEDS_CONVERSION-GEN)
	rm -rf ./pkg/apis/trust/v1alpha1/zz_generated.conversion.go

	$(CONVERSION-GEN) \
		--go-header-file=$(go_header_file) \
		--output-file=zz_generated.conversion.go \
		./pkg/apis/trust/v1alpha1

shared_generate_targets += generate-conversion

include make/kube-api-lint.mk
