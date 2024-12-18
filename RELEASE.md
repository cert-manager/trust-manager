# Releases

## Schedule

The release schedule for this project is ad-hoc. Given the pre-1.0 status of the project we do not have a fixed release cadence. However if a vulnerability is discovered we will respond in accordance with our [security policy](https://github.com/cert-manager/community/blob/main/SECURITY.md) and this response may include a release.

## Process

There is a semi-automated release process for this project. When you create a Git tag with a tagname that has a `v` prefix and push it to GitHub it will trigger the [release workflow].

The release process for this repo is documented below:

1. Create a tag for the new release:
    ```sh
   export VERSION=v0.5.0-alpha.0
   git tag --annotate --message="Release ${VERSION}" "${VERSION}"
   git push origin "${VERSION}"
   ```
2. A GitHub action will see the new tag and do the following:
    - Build and publish any container images
    - Build and publish the Helm chart
    - Create a draft GitHub release
3. Wait for the PR to be merged and wait for OCI Helm chart to propagate and become available from https://charts.jetstack.io (this might take a few hours).
4. Visit the [releases page], edit the draft release, click "Generate release notes", then edit the notes to add the following to the top
    ```
    trust-manager is the easiest way to manage security-critical TLS trust bundles in Kubernetes and OpenShift clusters.
    ```
5. Publish the release.

## Trust package

As well as the trust-manager container images, we also publish a trust package image. For more information on what a trust package is, see the [trust-packages readme](trust-packages/README.md). This process is fully automated through GitHub Actions:

1. A cron [GitHub Action](https://venafi.slack.com/archives/D06C21X5L13/p1717075543900969) checks for a new ca-certificates package and creates a PR updating `make/00_debian_version.mk` if one is found
2. Once merged a [GitHub Action](https://github.com/cert-manager/trust-manager/blob/main/.github/workflows/debian-trust-package-release.yaml) will build and release the container image.

## Artifacts

This repo will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images for the are published to `quay.io/jetstack`. 
- *Helm chart* - An official Helm chart is maintained within this repo and published to `quay.io/jetstack` and `charts.jetstack.io` on each release.

[release workflow]: https://github.com/cert-manager/trust-manager/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/trust-manager/releases