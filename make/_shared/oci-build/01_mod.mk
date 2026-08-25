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

$(bin_dir)/scratch/image:
	@mkdir -p $@

.PHONY: $(oci_build_targets)
## Build the OCI image.
## - oci-build-$(build_name) = build the oci directory (multi-arch)
## - oci-build-$(build_name)__local = build the oci directory (local arch: linux/$(HOST_ARCH))
## @category [shared] Build
$(oci_build_targets): oci-build-%: | $(NEEDS_KO) $(NEEDS_GO) $(NEEDS_YQ) $(NEEDS_IMAGE-TOOL) $(bin_dir)/scratch/image
	$(eval a := $(patsubst %__local,%,$*))
	$(eval is_local := $(if $(findstring $a__local,$*),true))
	$(eval layout_path := $(if $(is_local),$(oci_layout_path_$a).local,$(oci_layout_path_$a)))
	$(eval digest_path := $(if $(is_local),$(oci_digest_path_$a).local,$(oci_digest_path_$a)))

	rm -rf $(CURDIR)/$(layout_path)

	echo '{}' | \
		$(YQ) '.defaultBaseImage = "$(oci_$a_base_image)"' | \
		$(YQ) '.builds[0].id = "$a"' | \
		$(YQ) '.builds[0].dir = "$(go_$a_mod_dir)"' | \
		$(YQ) '.builds[0].main = "$(go_$a_main_dir)"' | \
		$(YQ) '.builds[0].env[0] = "CGO_ENABLED=$(go_$a_cgo_enabled)"' | \
		$(YQ) '.builds[0].env[1] = "GOEXPERIMENT=$(go_$a_goexperiment)"' | \
		$(YQ) '.builds[0].ldflags[0] = "-s"' | \
		$(YQ) '.builds[0].ldflags[1] = "-w"' | \
		$(YQ) '.builds[0].ldflags[2] = "{{.Env.LDFLAGS}}"' | \
		$(YQ) '.builds[0].flags[0] = "$(go_$a_flags)"' | \
		$(YQ) '.builds[0].linux_capabilities = "$(oci_$a_linux_capabilities)"' \
		> $(CURDIR)/$(layout_path).ko_config.yaml

	GOWORK=off \
	KO_DOCKER_REPO=$(oci_$a_image_name_development) \
	KOCACHE=$(CURDIR)/$(bin_dir)/scratch/image/ko_cache \
	KO_CONFIG_PATH=$(CURDIR)/$(layout_path).ko_config.yaml \
	SOURCE_DATE_EPOCH=$(GITEPOCH) \
	KO_GO_PATH=$(GO) \
	LDFLAGS="$(go_$a_ldflags)" \
	$(KO) build $(go_$a_mod_dir)/$(go_$a_main_dir) \
		--platform=$(if $(is_local),linux/$(HOST_ARCH),$(oci_$a_platforms)) \
		$(oci_$a_build_args) \
		--oci-layout-path=$(layout_path) \
		--sbom-dir=$(CURDIR)/$(layout_path).sbom \
		--sbom=spdx \
		--push=false \
		--bare

	$(IMAGE-TOOL) append-layers \
		$(CURDIR)/$(layout_path) \
		$(oci_$a_additional_layers)

	$(IMAGE-TOOL) list-digests \
		$(CURDIR)/$(layout_path) \
		> $(digest_path)

# Only include the oci-load target if kind is provided by the kind makefile-module
ifdef kind_cluster_name
.PHONY: $(oci_load_targets)
## Build OCI image for the local architecture and load
## it into the $(kind_cluster_name) kind cluster.
## @category [shared] Build
$(oci_load_targets): oci-load-%: docker-tarball-% | kind-cluster $(NEEDS_KIND)
	$(KIND) load image-archive --name $(kind_cluster_name) $(docker_tarball_path_$*)
endif

## Build Docker tarball image for the local architecture
## @category [shared] Build
.PHONY: $(docker_tarball_targets)
$(docker_tarball_targets): docker-tarball-%: oci-build-%__local | $(NEEDS_GO) $(NEEDS_IMAGE-TOOL)
	$(IMAGE-TOOL) convert-to-docker-tar $(CURDIR)/$(oci_layout_path_$*).local $(docker_tarball_path_$*) $(oci_$*_image_name_development):$(oci_$*_image_tag)
