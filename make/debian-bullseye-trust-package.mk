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

package_name_bullseye := cert-manager-debian-bullseye

debian_bullseye_package_json := $(debian_bullseye_package_layer)/debian-package/cert-manager-package-debian.json

$(debian_bullseye_package_layer)/debian-package:
	mkdir -p $@

$(debian_bullseye_package_json): | $(bin_dir)/bin/validate-trust-package $(debian_bullseye_package_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh exact $(DEBIAN_BULLSEYE_BUNDLE_SOURCE_IMAGE) $@ $(DEBIAN_BULLSEYE_BUNDLE_VERSION) $(package_name_bullseye)

# Make sure the build the package json file when building
# the OCI image. This will ensure that the $(debian_bullseye_package_layer)
# folder has the desired contents.
oci-build-package_debian_bullseye: $(debian_bullseye_package_json)
oci-build-package_debian_bullseye__local: $(debian_bullseye_package_json)

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

.PHONY: upgrade-debian-bullseye-trust-package-version
upgrade-debian-bullseye-trust-package-version: | $(bin_dir)/bin/validate-trust-package $(bin_dir)/scratch
	$(eval temp_out := $(bin_dir)/scratch/debian-bullseye-trust-package.temp.json)
	rm -rf $(temp_out)

	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh latest $(DEBIAN_BULLSEYE_BUNDLE_SOURCE_IMAGE) $(temp_out) $(DEBIAN_BULLSEYE_BUNDLE_VERSION) $(package_name_bullseye)

	latest_version=$$(jq -r '.version' $(temp_out)); \
		$(sed_inplace) "s/DEBIAN_BULLSEYE_BUNDLE_VERSION := .*/DEBIAN_BULLSEYE_BUNDLE_VERSION := $$latest_version/" make/00_debian_bullseye_version.mk

.PHONY: scan-debian-bullseye-trust-package
## Scan the latest Debian Bullseye trust package OCI image with Trivy
## @category [shared] Release
scan-debian-bullseye-trust-package: | $(NEEDS_TRIVY) $(NEEDS_CRANE)
	$(eval latest_bullseye_tag := $(shell $(CRANE) ls --omit-digest-tags $(oci_package_debian_bullseye_image_name) | sort -V | tail -n1))
	@echo "Scanning latest Debian Bullseye trust package: $(oci_package_debian_bullseye_image_name):$(latest_bullseye_tag)"
	$(TRIVY) image --exit-code 1 $(oci_package_debian_bullseye_image_name):$(latest_bullseye_tag)

