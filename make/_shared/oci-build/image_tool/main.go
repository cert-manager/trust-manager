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
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	"github.com/sigstore/cosign/v2/pkg/oci/signed"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: image_tool <command> [args]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list-digests":
		if len(os.Args) != 3 {
			fmt.Println("Usage: image_tool list-digests <path>")
			os.Exit(1)
		}
		err := listDigests(os.Args[2])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "convert-to-docker-tar":
		if len(os.Args) != 5 {
			fmt.Println("Usage: image_tool convert-to-docker-tar <path> <output> <image-name>")
			os.Exit(1)
		}
		err := convertToDockerTar(os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}

func listDigests(path string) error {
	ociLayout, err := layout.FromPath(path)
	if err != nil {
		return err
	}

	imageIndex, err := ociLayout.ImageIndex()
	if err != nil {
		return err
	}

	indexManifest, err := imageIndex.IndexManifest()
	if err != nil {
		return err
	}

	for _, man := range indexManifest.Manifests {
		fmt.Println(man.Digest)
	}

	return nil
}

func convertToDockerTar(path string, output string, imageName string) error {
	ociLayout, err := layout.FromPath(path)
	if err != nil {
		return err
	}

	imageIndex, err := ociLayout.ImageIndex()
	if err != nil {
		return err
	}

	matchingImages := []v1.Image{}
	_, err = mutate.Map(context.TODO(), signed.ImageIndex(imageIndex), func(_ context.Context, se oci.SignedEntity) (oci.SignedEntity, error) {
		switch obj := se.(type) {
		case oci.SignedImage:
			config, err := obj.ConfigFile()
			if err != nil {
				return nil, err
			}

			if config.Platform().Architecture == runtime.GOARCH {
				matchingImages = append(matchingImages, obj)
			}
		case oci.SignedImageIndex:
			// don't do anything
		default:
			return nil, fmt.Errorf("unrecognized type: %T", se)
		}

		return se, nil
	})
	if err != nil {
		return err
	}

	if len(matchingImages) == 0 {
		return fmt.Errorf("no matching images found")
	}

	if len(matchingImages) > 1 {
		return fmt.Errorf("multiple matching images found")
	}

	matchingImage := matchingImages[0]

	ref, err := name.ParseReference(imageName)
	if err != nil {
		return err
	}

	if err := tarball.WriteToFile(output, ref, matchingImage); err != nil {
		return err
	}

	return nil
}
