//go:build tools
// +build tools

// This file exists to force 'go mod' to fetch tool dependencies
// See: https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module

package bin

import (
	_ "github.com/onsi/ginkgo/v2"
	_ "k8s.io/code-generator/cmd/deepcopy-gen"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
	_ "sigs.k8s.io/kind"
)
