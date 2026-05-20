# Copyright 2026 The cert-manager Authors.
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

# Renders the trust-manager CRD as a single, ready-to-apply YAML file for
# attachment to GitHub Releases — same convenience as cert-manager's
# `cert-manager.crds.yaml`. See https://github.com/cert-manager/trust-manager/issues/142.
#
# Usage:
#   make render-crds
#   # produces $(crds_release_artifact)

crds_release_artifact := $(bin_dir)/scratch/trust-manager.crds.yaml

# Template against the packaged chart archive (not the source dir) so the
# rendered CRD picks up the chart's app-version from `helm package --app-version`
# rather than the unversioned `Chart.yaml` on disk. Without this the
# `app.kubernetes.io/version` label in the published CRD would be `v0.0.0`.
$(crds_release_artifact): $(helm_chart_archive) | $(NEEDS_HELM) $(NEEDS_YQ) $(bin_dir)/scratch
	$(HELM) template trust-manager $(helm_chart_archive) \
		--set crds.enabled=true \
		--set crds.keep=false \
		--show-only templates/crd-trust.cert-manager.io_bundles.yaml \
		--no-hooks \
		| $(YQ) 'del(.metadata.labels."app.kubernetes.io/managed-by", .metadata.labels."helm.sh/chart")' \
		> $@

.PHONY: render-crds
## Render the bundle CRD as a stand-alone YAML file suitable for kubectl apply.
## @category Release
render-crds: $(crds_release_artifact)
