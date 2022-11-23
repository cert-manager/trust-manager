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
FROM docker.io/library/golang:1.19 as builder

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

RUN go mod download

# Build
RUN make build

FROM scratch
LABEL description="cert-manager trust is an operator for distributing trust bundles across a Kubernetes cluster"

WORKDIR /
USER 1001
COPY --from=builder /workspace/bin/trust-manager /usr/bin/trust-manager

ENTRYPOINT ["/usr/bin/trust-manager"]
