<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/trust-manager"><img src="https://godoc.org/github.com/cert-manager/trust-manager?status.svg" alt="cert-manager/trust-manager godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/trust-manager"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/trust-manager" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
</p>

# trust-manager

trust-manager is an operator for distributing trust bundles across a Kubernetes cluster.
trust-manager is designed to complement
[cert-manager](https://github.com/cert-manager/cert-manager) by enabling services to
trust X.509 certificates signed by Issuers, as well as external CAs which may
not be known to cert-manager at all.

⚠️ trust-manager is still an early stage project and will undergo large changes as it's developed.

We'd encourage you to test it and we'd hope it'll be useful; just be prepared for breaking changes!

---

Please follow the documentation at
[cert-manager.io](https://cert-manager.io/docs/projects/trust-manager/) for
installing and using trust-manager.
