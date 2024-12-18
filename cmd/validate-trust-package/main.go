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
	"log"
	"os"
	"runtime/metrics"

	"github.com/cert-manager/trust-manager/pkg/fspkg"
)

func run(logger *log.Logger) int {
	_, err := fspkg.LoadPackage(os.Stdin)
	if err != nil {
		logger.Printf("failed to load and validate trust package: %s", err.Error())
		return 1
	}

	return 0
}

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	errVal := run(logger)

	negativeSerialSample := []metrics.Sample{{
		Name: "/godebug/non-default-behavior/x509negativeserial:events",
	}}
	metrics.Read(negativeSerialSample)

	negativeSerialCount := negativeSerialSample[0].Value.Uint64()
	if negativeSerialCount > 0 {
		logger.Printf("parsed %d certificate(s) with a negative serial number", negativeSerialCount)
	}

	os.Exit(errVal)
}
