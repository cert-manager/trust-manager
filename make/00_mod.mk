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

oci_platforms := linux/amd64,linux/arm/v7,linux/arm64,linux/ppc64le,linux/s390x

include make/00_debian_version.mk

repo_name := github.com/cert-manager/trust-manager

kind_cluster_name := trust-manager
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := manager package_debian

go_manager_main_dir := ./cmd/trust-manager
go_manager_mod_dir := .
go_manager_ldflags := -X $(repo_name)/internal/version.AppVersion=$(VERSION) -X $(repo_name)/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := static
oci_manager_image_name := quay.io/jetstack/trust-manager
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := cert-manager.local/trust-manager

go_package_debian_main_dir := .
go_package_debian_mod_dir := ./trust-packages/debian
go_package_debian_ldflags := 
oci_package_debian_base_image_flavor := static
oci_package_debian_image_name := quay.io/jetstack/cert-manager-package-debian
oci_package_debian_image_tag := $(DEBIAN_BUNDLE_VERSION)
oci_package_debian_image_name_development := cert-manager.local/cert-manager-package-debian

deploy_name := trust-manager
deploy_namespace := cert-manager

helm_chart_source_dir := deploy/charts/trust-manager
helm_chart_image_name := quay.io/jetstack/charts/trust-manager
helm_chart_version := $(VERSION)
helm_labels_template_name := trust-manager.labels

golangci_lint_config := .golangci.yaml

define helm_values_mutation_function
$(YQ) \
	'( .image.repository = "$(oci_manager_image_name)" ) | \
	( .image.tag = "$(oci_manager_image_tag)" ) | \
	( .defaultPackageImage.repository = "$(oci_package_debian_image_name)" ) | \
	( .defaultPackageImage.tag = "$(oci_package_debian_image_tag)" )' \
	$1 --inplace
endef
