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

It takes a list of trusted certificates which you specify and combines them into a bundle which you can trust directly
in your applications.

Supported sources include a public trust bundle similar to what you get from your Operating System.

[Installation instructions](https://cert-manager.io/docs/projects/trust-manager/) and [API reference documentation](https://cert-manager.io/docs/projects/trust-manager/api-reference/)
are available on the cert-manager website.

## Demo

If you've got Docker installed and you just want to play with trust-manager as soon as possible, we provide
a `demo` command to quickly get a [Kind cluster](https://kind.sigs.k8s.io/) running trust-manager.

First, clone the repo then run `make demo`:

```bash
git clone --single-branch https://github.com/cert-manager/trust-manager trust-manager
cd trust-manager
make demo
# kubeconfig is in ./bin/kubeconfig.yaml
# kind cluster is called "trust"
```

The demo installation uses Helm, and roughly matches what you'd get by installing trust-manager into your own
cluster using Helm - although it uses locally-built images rather than the ones we publish publicly.

## Example Bundle

The simplest useful Bundle to start with is likely to be one using default CAs, which are available from trust-manager 0.4.0+.

This default CA package is based on Debian's `ca-certificates` package, and so matches what you'd expect to see in a Debian
container or VM.

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

For more details see the [trust-manager documentation](https://cert-manager.io/docs/projects/trust-manager/).
