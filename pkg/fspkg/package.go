/*
Copyright 2022 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fspkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cert-manager/trust-manager/pkg/util"
)

type PackageType string

const (
	// PackageTypeStatic indicates that the package does not change once loaded. This is the default.
	// Currently, only static packages are supported and all other values for "Type" will be rejected.
	PackageTypeStatic PackageType = "static"
)

// Package specifies the structure of JSON packages which can be read from the filesystem
// of the trust-manager container and subsequently used in a Bundle resource
type Package struct {
	// Name contains a friendly name for the bundle
	Name string `json:"name"`

	// Bundle contains the PEM-formatted certificates which are provided by this bundle.
	Bundle string `json:"bundle"`

	// Version identifies the bundle's version, to distinguish updated bundles from older counterparts
	Version string `json:"version"`

	// Type identifies how the bundle should be consumed. Provided for future-use;
	// the only valid value currently is PackageTypeStatic
	Type PackageType `json:"type"`
}

// StringID returns a human-readable string ID which should allow one package to be easily distinguished from another.
func (p Package) StringID() string {
	bundleHash := sha256.Sum256([]byte(p.Bundle))

	return fmt.Sprintf("%s-%s-%s-%s", p.Name, p.Version, p.Type, hex.EncodeToString(bundleHash[:8]))
}

// Clone returns a new copy of the given package
func (p *Package) Clone() *Package {
	return &Package{
		Name:    p.Name,
		Bundle:  p.Bundle,
		Version: p.Version,
		Type:    p.Type,
	}
}

// LoadPackage attempts to read a package from the given path
func LoadPackage(path string) (Package, error) {
	// Only try to read files ending in ".json"
	if filepath.Ext(path) != ".json" {
		return Package{}, fmt.Errorf("can't load package at path '%s' since it doesn't have the required .json extension", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return Package{}, fmt.Errorf("failed to open package on filesystem '%s': %w", path, err)
	}
	defer f.Close()

	var pkg Package

	if err := json.NewDecoder(f).Decode(&pkg); err != nil {
		return Package{}, fmt.Errorf("failed to parse package JSON at path '%s': %w", path, err)
	}

	if pkg.Type == "" {
		pkg.Type = PackageTypeStatic
	}

	// Ignore the sanitized bundle here and preserve the bundle as-is.
	// We'll sanitize later, when building a bundle on a reconcile.
	// We validate here so we can error when loading rather than just erroring at the time of use
	_, err = util.ValidateAndSanitizePEMBundle([]byte(pkg.Bundle))
	if err != nil {
		return Package{}, fmt.Errorf("package '%s' failed validation: %w", path, err)
	}

	if pkg.Type != PackageTypeStatic {
		return Package{}, fmt.Errorf("invalid package '%s'; only supported type currently is '%s'", path, PackageTypeStatic)
	}

	return pkg, nil
}
