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
	"io"
	"os"
	"path/filepath"

	"github.com/cert-manager/trust-manager/pkg/util"
)

// Package specifies the structure of JSON packages which can be read from the filesystem
// of the trust-manager container and subsequently used in a Bundle resource.
// Note that this struct must be both forwards and backwards compatible. Any JSON which
// marshals / unmarshals from this struct should be readable by every version of trust-manager
// which supports loading default CA packages.
type Package struct {
	// Name contains a friendly name for the bundle
	Name string `json:"name"`

	// Bundle contains the PEM-formatted certificates which are provided by this bundle.
	Bundle string `json:"bundle"`

	// Version identifies the bundle's version, to distinguish updated bundles from older counterparts
	Version string `json:"version"`
}

// StringID returns a human-readable string ID which should allow one package to be easily distinguished from another.
func (p Package) StringID() string {
	bundleHash := sha256.Sum256([]byte(p.Bundle))

	return fmt.Sprintf("%s-%s-%s", p.Name, p.Version, hex.EncodeToString(bundleHash[:8]))
}

// Clone returns a new copy of the given package
func (p *Package) Clone() *Package {
	return &Package{
		Name:    p.Name,
		Bundle:  p.Bundle,
		Version: p.Version,
	}
}

// Validate checks that the given package is valid. All packages must successfully validate before being accepted for use.
func (p *Package) Validate() error {
	// Ignore the sanitized bundle here and preserve the bundle as-is.
	// We'll sanitize later, when building a bundle on a reconcile.
	_, err := util.ValidateAndSanitizePEMBundle([]byte(p.Bundle))
	if err != nil {
		return fmt.Errorf("package bundle failed validation: %w", err)
	}

	if len(p.Name) == 0 {
		return fmt.Errorf("package may not have an empty 'name'")
	}

	if len(p.Version) == 0 {
		return fmt.Errorf("package may not have an empty 'version'")
	}

	return nil
}

// LoadPackage tries to read a package from the given reader, checking that it only contains valid certificates
func LoadPackage(reader io.Reader) (Package, error) {
	var pkg Package

	if err := json.NewDecoder(reader).Decode(&pkg); err != nil {
		return Package{}, fmt.Errorf("failed to parse package JSON: %w", err)
	}

	// We validate here so we can error when loading rather than just erroring at the time of use
	if err := pkg.Validate(); err != nil {
		return Package{}, err
	}

	return pkg, nil
}

const requiredExt = ".json"

// LoadPackageFromFile uses LoadPackage to read a JSON file specifying a package
func LoadPackageFromFile(path string) (Package, error) {
	// Only try to read files ending in ".json"
	if filepath.Ext(path) != requiredExt {
		return Package{}, fmt.Errorf("can't load package at path %q since it doesn't have the required %q extension", path, requiredExt)
	}

	f, err := os.Open(path)
	if err != nil {
		return Package{}, fmt.Errorf("failed to open package on filesystem %q: %w", path, err)
	}

	defer f.Close()

	pkg, err := LoadPackage(f)
	if err != nil {
		return Package{}, fmt.Errorf("failed to load package %q: %w", path, err)
	}

	return pkg, nil
}
