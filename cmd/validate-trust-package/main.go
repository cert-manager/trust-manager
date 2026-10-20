/*
Copyright 2023 The cert-manager Authors.

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

package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cert-manager/trust-manager/pkg/denylist"
	"github.com/cert-manager/trust-manager/pkg/fspkg"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "validate-trust-package: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stderr io.Writer) error {
	flags := flag.NewFlagSet("validate-trust-package", flag.ContinueOnError)
	flags.SetOutput(stderr)

	denylistPath := flags.String("denylist", "", "optional path to a JSON file listing distrusted roots which must not appear in the package")

	if err := flags.Parse(args); err != nil {
		return err
	}

	pkg, err := fspkg.LoadPackage(stdin)
	if err != nil {
		return fmt.Errorf("failed to load and validate trust package: %w", err)
	}

	if *denylistPath == "" {
		return nil
	}

	distrusted, err := denylist.LoadFile(*denylistPath)
	if err != nil {
		return err
	}

	if err := checkAbsent(pkg.Bundle, distrusted); err != nil {
		return err
	}

	fmt.Fprintf(stderr, "+++ confirmed none of the %d distrusted roots in %s are present in the package\n", distrusted.Len(), *denylistPath)

	return nil
}

// checkAbsent fails if any denylisted root is present in the bundle.
//
// The invariant deliberately isn't "N certificates were removed" - that
// depends on what Debian happened to ship, so it would false-fail as soon as
// upstream removes a root for us. "No denylisted fingerprint appears in the
// output" holds either way, and catches the filter being skipped, the filter
// being buggy, or the wrong file being wired into the package JSON.
func checkAbsent(bundle string, distrusted *denylist.Denylist) error {
	var found []string

	rest := []byte(bundle)

	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		fingerprint := denylist.FingerprintCert(block.Bytes)

		if entry, denied := distrusted.Lookup(fingerprint); denied {
			found = append(found, fmt.Sprintf("%s (%s)", fingerprint, entry.Reason))
		}
	}

	if len(found) > 0 {
		var message strings.Builder

		fmt.Fprintf(&message, "package contains %d distrusted root(s) which should have been filtered out:", len(found))

		for _, entry := range found {
			message.WriteString("\n  " + entry)
		}

		return fmt.Errorf("%s", message.String())
	}

	return nil
}
