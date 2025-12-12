# Copyright 2025 The cert-manager Authors.
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

package_name_bookworm := cert-manager-debian-bookworm

debian_bookworm_package_json := $(debian_bookworm_package_layer)/debian-package/cert-manager-package-debian.json

$(debian_bookworm_package_layer)/debian-package:
	mkdir -p $@

$(debian_bookworm_package_json): | $(bin_dir)/bin/validate-trust-package $(debian_bookworm_package_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh exact $(DEBIAN_BOOKWORM_BUNDLE_SOURCE_IMAGE) $@ $(DEBIAN_BOOKWORM_BUNDLE_VERSION) $(package_name_bookworm)

# Make sure the build the package json file when building
# the OCI image. This will ensure that the $(debian_bookworm_package_layer)
# folder has the desired contents.
oci-build-package_debian_bookworm: $(debian_bookworm_package_json)
oci-build-package_debian_bookworm__local: $(debian_bookworm_package_json)

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

.PHONY: upgrade-debian-bookworm-trust-package-version
upgrade-debian-bookworm-trust-package-version: | $(bin_dir)/bin/validate-trust-package $(bin_dir)/scratch
	$(eval temp_out := $(bin_dir)/scratch/debian-bookworm-trust-package.temp.json)
	rm -rf $(temp_out)

	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh latest $(DEBIAN_BOOKWORM_BUNDLE_SOURCE_IMAGE) $(temp_out) $(DEBIAN_BOOKWORM_BUNDLE_VERSION) $(package_name_bookworm)

	latest_version=$$(jq -r '.version' $(temp_out)); \
		$(sed_inplace) "s/DEBIAN_BOOKWORM_BUNDLE_VERSION := .*/DEBIAN_BOOKWORM_BUNDLE_VERSION := $$latest_version/" make/00_debian_bookworm_version.mk


.PHONY: scan-debian-bookworm-trust-package
## Scan the latest Debian Bookworm trust package OCI image with Trivy
## @category [shared] Release
scan-debian-bookworm-trust-package: | $(NEEDS_TRIVY) $(NEEDS_CRANE)
	@# We explicitly exclude the tag "20230311.0" here because it breaks version comparisons with "sort -V" and compares as newer than the other tags.
	@# Even with that tag excluded, this is brittle; the current format used for the tag doesn't allow us to easily
	@# answer the question "which tag is latest" without more custom logic. For now, this works but for future trust packages it might be worth considering our own version format.
	$(eval latest_bookworm_tag := $(shell $(CRANE) ls --omit-digest-tags $(oci_package_debian_bookworm_image_name) | grep -v "20230311.0" | sort -V | tail -n1))
	@echo "Scanning latest Debian Bookworm trust package: $(oci_package_debian_bookworm_image_name):$(latest_bookworm_tag)"
	$(TRIVY) image --exit-code 1 $(oci_package_debian_bookworm_image_name):$(latest_bookworm_tag)
