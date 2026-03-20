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
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var waitFlag = flag.Bool("wait", false, "if true, wait for a signal before exiting\nif false, exit with a status code after copying")

// usage ensures that printing arg defaults from the flag package goes through the logger
func usage(logger *log.Logger) func() {
	return func() {
		logger.Printf("usage: %s [flags] <input-folder> <output-folder>", os.Args[0])

		buf := &bytes.Buffer{}

		flag.CommandLine.SetOutput(buf)
		flag.PrintDefaults()

		for line := range strings.SplitSeq(buf.String(), "\n") {
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

	var inputDir, destinationDir string
	switch {
	case flag.NArg() == 3 && flag.Arg(0) == "/copyandmaybepause":
		stderrLogger.Printf("DEPRECATED: use the image's entrypoint instead of /copyandmaybepause")
		inputDir = flag.Arg(1)
		destinationDir = flag.Arg(2)
	case flag.NArg() == 2:
		inputDir = flag.Arg(0)
		destinationDir = flag.Arg(1)
	default:
		flag.Usage()
		os.Exit(1)
	}

	if err := copyInputToOutput(stderrLogger, inputDir, destinationDir); err != nil {
		stderrLogger.Fatal(err)
	}

	if *waitFlag {
		stderrLogger.Printf("finished copying, waiting for termination signal")

		// TODO: if we add the ability to reap zombie processes, this could function as a full init

		sigs := make(chan os.Signal, 1)

		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs

		stderrLogger.Println("received interrupt, closing")
	}
}

func copyInputToOutput(stderrLogger *log.Logger, srcPath, dstPath string) error {
	stderrLogger.Printf("reading from %s", srcPath)
	stderrLogger.Printf("writing to   %s", dstPath)

	closeWithLog := func(f io.Closer) {
		if err := f.Close(); err != nil {
			stderrLogger.Printf("error: failed to close: %s", err.Error())
		}
	}

	srcRoot, err := os.OpenRoot(srcPath)
	if err != nil {
		return fmt.Errorf("couldn't confirm that input path is a directory that exists: %w", err)
	}
	defer closeWithLog(srcRoot)

	dstRoot, err := os.OpenRoot(dstPath)
	if err != nil {
		return fmt.Errorf("couldn't confirm that output path is a directory that exists: %w", err)
	}
	defer closeWithLog(dstRoot)

	return fs.WalkDir(srcRoot.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// For logging purposes, we want to report the real paths
		realSrcPath := filepath.Join(srcPath, path)
		realDstPath := filepath.Join(dstPath, path)

		if d.IsDir() {
			return dstRoot.MkdirAll(path, 0o755)
		}

		if !d.Type().IsRegular() {
			return nil // skip non-regular files (e.g. symlinks, devices)
		}

		if filepath.Ext(path) != ".json" {
			return nil
		}

		r, err := srcRoot.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %q for reading: %w", realSrcPath, err)
		}
		defer closeWithLog(r)

		// Flatten the directory structure
		flatPath := filepath.Base(path)
		w, err := dstRoot.OpenFile(flatPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open file %q for writing: %w", realDstPath, err)
		}
		defer closeWithLog(w)

		if _, err := io.Copy(w, r); err != nil {
			return fmt.Errorf("failed to copy source %q to destination %q: %w", realSrcPath, realDstPath, err)
		}

		stderrLogger.Printf("successfully copied %s to %s", realSrcPath, realDstPath)

		return nil
	})
}
