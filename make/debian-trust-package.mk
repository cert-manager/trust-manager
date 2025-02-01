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

package_name := cert-manager-debian

debian_package_layer := $(bin_dir)/scratch/debian-trust-package
debian_package_json := $(debian_package_layer)/debian-package/cert-manager-package-debian.json

$(debian_package_layer)/debian-package:
	mkdir -p $@

$(debian_package_json): | $(bin_dir)/bin/validate-trust-package $(debian_package_layer)/debian-package
	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh exact $(DEBIAN_BUNDLE_SOURCE_IMAGE) $@ $(DEBIAN_BUNDLE_VERSION) $(package_name)

# Make sure the build the package json file when building
# the OCI image. This will ensure that the $(debian_package_layer)
# folder has the desired contents.
oci-build-package_debian: $(debian_package_json)

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

.PHONY: upgrade-debian-trust-package-version
upgrade-debian-trust-package-version: | $(bin_dir)/bin/validate-trust-package $(bin_dir)/scratch
	$(eval temp_out := $(bin_dir)/scratch/debian-trust-package.temp.json)
	rm -rf $(temp_out)

	BIN_VALIDATE_TRUST_PACKAGE=$(bin_dir)/bin/validate-trust-package \
		./make/debian-trust-package-fetch.sh latest $(DEBIAN_BUNDLE_SOURCE_IMAGE) $(temp_out) $(DEBIAN_BUNDLE_VERSION) $(package_name)

	latest_version=$$(jq -r '.version' $(temp_out)); \
		$(sed_inplace) "s/DEBIAN_BUNDLE_VERSION := .*/DEBIAN_BUNDLE_VERSION := $$latest_version/" make/00_debian_version.mk
