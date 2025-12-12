# Releases

trust-manager has several release artifacts including:

- A container image for the trust-manager controller
- An official Helm chart
- "Trust package" container images containing CA certificates (see [trust-packages readme](trust-packages/README.md) for more information)

## Release Process Flow

1.  Before releasing anything, run a security scan to check for any unpatched vulnerabilities:

   ```sh
   make prerelease-scan
   ```

   This will scan the latest versions of the trust packages images, as well as scanning the trust-manager codebase using govulncheck. If it reports a vulnerability that needs to be addressed, fix it before proceeding with the release.

1. a. (If required) Update the trust package images. See the "Trust packages" section below for more information on how to do that.
      The values.yaml file for the Helm chart is automatically set to point at the latest patch release of the latest
      trust package version at build time.

2. Proceed with the trust-manager controller and Helm chart release process. See the "trust-manager Controller and Helm Chart" section below for more information on how to do that.

## Release Schedule

The release schedule for this project is ad-hoc. Given the pre-1.0 status of the project we do not have a fixed release cadence. However if a vulnerability is discovered we will respond in accordance with our [security policy](https://github.com/cert-manager/community/blob/main/SECURITY.md) and this response may include a release.

## Process

### trust-manager Controller and Helm Chart

There is a semi-automated release process for this project. When you create a Git tag with a tagname that has a `v` prefix and push it to GitHub it will trigger the [release workflow].

The release process for this repo is documented below:

1. Create a tag for the new release:
    ```sh
   export VERSION=v0.5.0-alpha.0
   git tag --annotate --message="Release ${VERSION}" "${VERSION}"
   git push origin "${VERSION}"
   ```

2. A GitHub action will see the new tag and do the following:
    - Build and publish the controller container image
    - Build and publish the Helm chart
    - Create a draft GitHub release

3. Visit the [releases page], edit the draft release, click "Generate release notes", then edit the notes to add the following to the top
    ```
    trust-manager is the easiest way to manage security-critical TLS trust bundles in Kubernetes and OpenShift clusters.
    ```

4. Publish the GitHub release, and announce the release in relevant channels!

### Trust packages

As well as the trust-manager container images, we also publish a trust package image. For more information on what a trust package is, see the [trust-packages readme](trust-packages/README.md). This process is fully automated through GitHub Actions:

1. A cron GitHub Action (`.github/workflows/trust-package-upgrade-debian-<version>.yaml`) checks for a new ca-certificates package and creates a PR updating `make/00_debian_<version>_version.mk` if an upgrade is found
2. When `make/00_debian_<version>_version.mk` is changed in a PR, a different GitHub Action (`.github/workflows/trust-package-release-debian-<version>.yaml`) will build and release the container image.

## Artifacts

This repo will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images for trust-manager are published to `quay.io/jetstack`.
- *Helm chart* - An official Helm chart is maintained within this repo and published to `quay.io/jetstack` and `charts.jetstack.io` on each release.
   Note that the legacy Helm repository at `charts.jetstack.io` may take longer to update than the OCI chart, since it requires a separate review by a CyberArk team member.

[release workflow]: https://github.com/cert-manager/trust-manager/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/trust-manager/releases
