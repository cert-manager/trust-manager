/*
Copyright 2026 The cert-manager Authors.

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

// Command filter-trust-package reads a PEM bundle on stdin, removes any
// certificate whose SHA-256 fingerprint appears in the given denylist, and
// writes the remaining certificates to stdout in their original order.
//
// It's used when building the Debian trust packages, between copying
// /etc/ssl/certs/ca-certificates.crt out of the container and wrapping it in
// the package JSON, so that the bundle we ship is filtered and the existing
// validation step validates exactly what we ship.
package main

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cert-manager/trust-manager/pkg/compat"
	"github.com/cert-manager/trust-manager/pkg/denylist"
)

// pemBeginPrefix is the start of every PEM block's BEGIN line. It can't appear
// anywhere else in a well-formed block, since the base64 alphabet has no "-".
const pemBeginPrefix = "-----BEGIN "

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "filter-trust-package: %s\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("filter-trust-package", flag.ContinueOnError)
	flags.SetOutput(stderr)

	denylistPath := flags.String("denylist", "", "path to a JSON file listing the distrusted roots to remove (required)")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if *denylistPath == "" {
		return fmt.Errorf("--denylist must be set to the path of a distrusted roots file")
	}

	distrusted, err := denylist.LoadFile(*denylistPath)
	if err != nil {
		return err
	}

	input, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("failed to read bundle from stdin: %w", err)
	}

	filtered, err := filter(input, distrusted, stderr)
	if err != nil {
		return err
	}

	// Only write anything to stdout once we know the whole input was good;
	// stdout is redirected to a file by the build, and a partially written
	// bundle would be worse than no bundle at all.
	if _, err := stdout.Write(filtered); err != nil {
		return fmt.Errorf("failed to write filtered bundle to stdout: %w", err)
	}

	return nil
}

// filter returns the input bundle with every denylisted certificate removed,
// reporting what it removed to the given writer.
//
// Certificates are re-encoded rather than copied verbatim, so the output is
// canonical PEM regardless of how the input was wrapped. The order of the
// retained certificates is preserved.
func filter(input []byte, distrusted *denylist.Denylist, report io.Writer) ([]byte, error) {
	var output bytes.Buffer

	var total, removed int

	rest := input

	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}

		// pem.Decode silently skips over anything which isn't a PEM block, so
		// check for ourselves that the next thing in the input really is one.
		// Otherwise we'd quietly drop data we were never asked to remove.
		if !bytes.HasPrefix(rest, []byte(pemBeginPrefix)) {
			return nil, fmt.Errorf("invalid bundle: found data which is not a PEM block, %d bytes from the end of the input", len(rest))
		}

		var block *pem.Block

		undecoded := rest

		block, rest = pem.Decode(undecoded)
		if block == nil {
			return nil, fmt.Errorf("invalid bundle: failed to decode a PEM block, %d bytes from the end of the input", len(undecoded))
		}

		// The prefix check above isn't enough on its own: a block whose base64
		// body is corrupt also starts with a BEGIN line, and pem.Decode skips
		// over it to return the next block which does decode. We know the input
		// started with a BEGIN line, so if the bytes pem.Decode consumed hold
		// more than one then it skipped at least one malformed block, and we'd
		// be dropping a certificate we were never asked to remove. A base64
		// body can't contain a BEGIN line itself, so counting is exact.
		if consumed := undecoded[:len(undecoded)-len(rest)]; bytes.Count(consumed, []byte(pemBeginPrefix)) != 1 {
			return nil, fmt.Errorf("invalid bundle: found a malformed PEM block which would have been skipped, %d bytes from the end of the input", len(undecoded))
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("invalid bundle: only CERTIFICATE blocks are permitted but found %q", block.Type)
		}

		if len(block.Headers) != 0 {
			return nil, fmt.Errorf("invalid bundle: PEM blocks are not permitted to have headers")
		}

		total++

		// Fingerprint the DER directly rather than a parsed certificate, so
		// that a certificate we can't parse can still be matched and removed.
		fingerprint := denylist.FingerprintCert(block.Bytes)

		if entry, found := distrusted.Lookup(fingerprint); found {
			removed++

			// Parsing is best effort for a certificate we're about to throw
			// away: we only want it for the report, and refusing to remove an
			// explicitly denied root because we can't parse it would leave us
			// unable to build a clean bundle at all.
			//
			// Report the subject parsed from the certificate we actually
			// removed, rather than a name copied into the denylist, since the
			// former can't drift from reality.
			subject := "<unparseable certificate>"
			if certificate, err := compat.ParseCertificate(block.Bytes); err == nil {
				subject = certificate.Subject.String()
			}

			fmt.Fprintf(report, "+++ removing %s (%s)\n", fingerprint, subject)
			fmt.Fprintf(report, "      reason: %s\n", entry.Reason)

			continue
		}

		// A certificate we're keeping is one we're about to ship, so it has to
		// parse, bar the compatibility exceptions compat knows about.
		if _, err := compat.ParseCertificate(block.Bytes); err != nil && !compat.IsSkipError(err) {
			return nil, fmt.Errorf("invalid bundle: failed to parse certificate with fingerprint %s: %w", fingerprint, err)
		}

		if err := pem.Encode(&output, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return nil, fmt.Errorf("failed to encode certificate with fingerprint %s: %w", fingerprint, err)
		}
	}

	if total == 0 {
		return nil, fmt.Errorf("invalid bundle: input contained no certificates")
	}

	// Removing nothing is an expected steady state, not a fault: half the
	// denylist is there defensively and has nothing to match, and upstream
	// Debian may remove a listed root for us at any refresh. The guarantee we
	// actually care about - that no denylisted root is in the bundle we ship -
	// is enforced by validate-trust-package over the final JSON.
	fmt.Fprintf(report, "+++ removed %d of %d certificates\n", removed, total)

	if output.Len() == 0 {
		return nil, fmt.Errorf("refusing to emit an empty bundle: all %d certificates were removed", total)
	}

	return output.Bytes(), nil
}
