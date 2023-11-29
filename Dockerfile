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

# Build the trust binary
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.21 as builder

ARG GOPROXY
ARG TARGETARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# Copy build scripts
COPY Makefile Makefile
COPY make/ make/

# Copy the go source files
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY hack/ hack/

RUN GOPROXY=$GOPROXY go mod download

# Build
RUN make build-linux-$TARGETARCH

FROM scratch

ARG TARGETARCH

LABEL description="trust-manager is an operator for distributing trust bundles across a Kubernetes cluster"

WORKDIR /
USER 1001
COPY --from=builder /workspace/bin/trust-manager-linux-$TARGETARCH /usr/bin/trust-manager

ENTRYPOINT ["/usr/bin/trust-manager"]
