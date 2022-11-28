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
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	stderrLogger := log.New(os.Stderr, "", log.LstdFlags)

	if len(os.Args) != 3 {
		stderrLogger.Fatalf("usage: %s <input-folder> <output-folder>", os.Args[0])
	}

	inputDir := os.Args[1]
	destinationDir := os.Args[2]

	stderrLogger.Printf("reading from %q", inputDir)
	stderrLogger.Printf("writing to %q", destinationDir)

	if err := dirOrError(inputDir); err != nil {
		stderrLogger.Fatalf("couldn't confirm that input path is a directory that exists: %s", err.Error())
	}

	if err := dirOrError(destinationDir); err != nil {
		stderrLogger.Fatalf("couldn't confirm that output path is a directory that exists: %s", err.Error())
	}

	walkErr := filepath.Walk(inputDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		var input *os.File
		var target *os.File

		input, err = os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %q for reading: %w", path, err)
		}

		defer func() {
			err := input.Close()
			if err != nil {
				stderrLogger.Printf("failed to close input file: %s", err.Error())
			}
		}()

		destinationFile := filepath.Join(destinationDir, filepath.Base(path))

		target, err = os.OpenFile(destinationFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o664)
		if err != nil {
			return fmt.Errorf("failed to open file %q for writing: %w", destinationFile, err)
		}

		defer func() {
			err := target.Close()
			if err != nil {
				stderrLogger.Printf("failed to close output file: %s", err.Error())
			}
		}()

		if _, err := io.Copy(target, input); err != nil {
			return fmt.Errorf("failed to copy source %q to destination %q: %w", path, destinationFile, err)
		}

		stderrLogger.Printf("successfully copied %q to %q", path, destinationFile)

		return nil
	})

	if walkErr != nil {
		stderrLogger.Fatalf("failed to walk input dir %q: %s", inputDir, walkErr.Error())
	}

	stderrLogger.Printf("finished copying, waiting for termination signal")

	// TODO: if we add the ability to reap zombie processes, this could function as a full init

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	stderrLogger.Println("received interrupt, closing")
}

func dirOrError(name string) error {
	info, err := os.Stat(name)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", name)
	}

	return nil
}
