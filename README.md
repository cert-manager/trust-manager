<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/trust-manager"><img src="https://godoc.org/github.com/cert-manager/trust-manager?status.svg" alt="cert-manager/trust-manager godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/trust-manager"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/trust-manager" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
</p>

# trust-manager

trust-manager is the easiest way to manage trust bundles in Kubernetes and OpenShift clusters.

It orchestrates bundles of trusted X.509 certificates which are primarily used for validating
certificates during a TLS handshake but can be used in other situations, too.

⚠️ trust-manager is still an early stage project and may undergo large changes as it's developed.

We'd encourage you to test it and we believe it's useful, but while we'll strive to avoid any
breaking changes we reserve the right to break things if we must!

---

Please follow the documentation on [cert-manager.io](https://cert-manager.io/docs/projects/trust-manager/) to
install trust-manager.

## Demo

If you've got Docker installed and you just want to play with trust-manager as soon as possible, we provide
a `demo` command to get a [Kind cluster](https://kind.sigs.k8s.io/) set up with minimal fuss.

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
