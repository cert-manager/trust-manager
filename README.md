<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/trust-manager"><img src="https://godoc.org/github.com/cert-manager/trust-manager?status.svg" alt="cert-manager/trust-manager godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/trust-manager"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/trust-manager" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
</p>

# trust-manager

trust-manager is the easiest way to manage trust bundles in Kubernetes and OpenShift clusters!

It takes a list of trusted certificate sources and combines them into a bundle which you can trust directly
in your applications.

Supported sources include a public trust bundle similar to what you get from your Operating System.

trust-manager documentation is available on the cert-manager website, including:

- [Installation instructions](https://cert-manager.io/docs/trust/trust-manager/installation/)
- [Usage guidance](https://cert-manager.io/docs/trust/trust-manager/)
- [API reference documentation](https://cert-manager.io/docs/trust/trust-manager/api-reference/)

## Developing trust-manager

trust-manager uses [makefile-modules](https://github.com/cert-manager/makefile-modules/), meaning that any changes to files under `make/_shared` need to be made in that repo and synchronized here using `make upgrade-klone`.

The easiest way to get started is to run the trust-manager smoke tests locally.

Use `make test-smoke`, which creates a [Kind cluster](https://kind.sigs.k8s.io/) using Docker and installs trust-manager (and cert-manager) before running the tests.

To create a cluster without running the smoke tests, use `make test-smoke-deps`.

To use or inspect the cluster, the `KUBECONFIG` file needs to be made available:

```console
export KUBECONFIG=$(pwd)/_bin/scratch/kube.config
```

### Testing

trust-manager has various categories of tests. All categories are run against every PR, along with other checks.

- `make test-unit` - Runs simpler, faster tests which test specific functions
- `make test-integration` - Runs heavier tests with a simplified control-plane which tests how different pieces work together
- `make test-smoke` - Runs end-to-end tests in a dedicated Kubernetes cluster

## Example Bundle

The simplest useful Bundle uses default CAs. This default CA package is based on Debian's `ca-certificates` package, and so matches what you'd expect to see in a Debian container or VM.

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: trust-manager-bundle
spec:
  sources:
  - useDefaultCAs: true
  target:
    configMap:
      key: "bundle.pem"
```

This Bundle will lead to a ConfigMap called `trust-manager-bundle` containing the default CAs being created in all namespaces, ready to be mounted
and used by your applications.

Your ConfigMap will automatically be updated if you change your bundle, too - so to update it, simply update your Bundle!

For more details see the [trust-manager documentation](https://cert-manager.io/docs/trust/trust-manager/).
