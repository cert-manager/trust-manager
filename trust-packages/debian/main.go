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

package main

import (
	"bytes"
	"embed"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

//go:embed debian-trust-package.json
var input embed.FS

// usage ensures that printing arg defaults from the flag package goes through the logger
func usage(logger *log.Logger) func() {
	return func() {
		logger.Printf("usage: %s [flags] <output-file>", os.Args[0])

		buf := &bytes.Buffer{}

		flag.CommandLine.SetOutput(buf)
		flag.PrintDefaults()

		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}

			logger.Println(line)
		}
	}
}

func main() {
	stderrLogger := log.New(os.Stderr, "", log.LstdFlags)

	flag.Usage = usage(stderrLogger)

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	destinationFile := flag.Arg(0)
	destinationFolder := filepath.Dir(destinationFile)

	if err := os.MkdirAll(destinationFolder, 0o755); err != nil {
		stderrLogger.Fatalf("failed to create directory %q: %s", destinationFolder, err.Error())
	}

	target, err := os.OpenFile(destinationFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o664)
	if err != nil {
		stderrLogger.Fatalf("failed to open file %q for writing: %w", destinationFile, err)
	}

	defer func() {
		err := target.Close()
		if err != nil {
			stderrLogger.Printf("failed to close output file: %s", err.Error())
		}
	}()

	inputFile, err := input.Open("debian-trust-package.json")
	if err != nil {
		stderrLogger.Fatalf("failed to open embedded file: %w", err)
	}

	if _, err := io.Copy(target, inputFile); err != nil {
		stderrLogger.Fatalf("failed to copy source to destination %q: %w", destinationFile, err)
	}

	stderrLogger.Printf("successfully copied to %s", destinationFile)
}
