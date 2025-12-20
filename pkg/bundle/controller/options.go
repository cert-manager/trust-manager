/*
Copyright 2025 The cert-manager Authors.

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

package controller

// Options hold options for the Bundle controller.
type Options struct {
	// Namespace is the trust Namespace that source data can be referenced.
	Namespace string

	// DefaultPackageLocation is the location on the filesystem from which the 'default'
	// certificate package should be loaded. If set, a valid package must be successfully
	// loaded in order for the controller to start. If unset, referring to the default
	// certificate package in a `Bundle` resource will cause that Bundle to error.
	DefaultPackageLocation string

	// SecretTargetsEnabled controls if secret targets are enabled in the Bundle API.
	SecretTargetsEnabled bool

	// FilterExpiredCerts controls if expired certificates are filtered from the bundle.
	FilterExpiredCerts bool

	// Limit both the manager and target caches to the provided list of namespaces
	TargetNamespaces []string

	// Filter non-CA certificates, only CAs are used in the resulting Bundle
	FilterNonCACerts bool
}
