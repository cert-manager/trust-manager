# Design: Source Plugins

## Summary

trust-manager has always supported a variety of trust sources: Secrets, ConfigMaps, "inLine" PEM data and the public trust bundles are
all sources of trust data today. All of these sources make sense for trust-manager to support directly.

There are other sources which might not make sense for trust-manager to support directly, but which are useful for users to be able to
include in their trust-manager targets. Examples include:

- Files from container images (e.g. `/etc/ssl/certs/ca-certificates.crt` from a Debian image)
- Files sources from an HTTP server (e.g. the Mozilla CA bundle)
- Enterprise trust stores (e.g. Microsoft Active Directory, CyberArk Workload Identity Manager, AWS PrivateCA, etc.)

This document describes a design for a source plugin system which allows users to add sources of trust data such as these to their
trust-manager bundles.

## Goals

- Allow for users to implement a custom source of trust data without interacting with the trust-manager codebase

## Non-Goals

- Changes to existing trust-manager sources (e.g. Secrets, ConfigMaps)

## Proposal

The direction of travel for for the trust-manager API interface is described by [PR#647](https://github.com/cert-manager/trust-manager/pull/647), which changes source types from keys in a map to a free-form "kind" string. This enables the use of arbitrary kinds of sources, including those which are not built-in to trust-manager. Specifically, this enables the use of CRDs to define sources of trust data.

For example, a source plugin for a file in a container image could be implemented as follows:

```yaml
spec:
  sources:
  - kind: ImageTrustSource
    apiVersion: example.io/v1alpha1
    name: example
```

In this example, `ImageTrustSource` is a CRD, and trust-manager can query this named resource to retrieve trust data. For example, the
YAML for the `ImageTrustSource` CRD might look like this:

```yaml
apiVersion: example.io/v1alpha1
kind: ImageTrustSource
metadata:
  name: example
spec:
  image: docker.io/library/debian:bookworm
  path: /etc/ssl/certs/ca-certificates.crt
```

Running in the same cluster, a plugin controller would watch for changes to `ImageTrustSource` resources and update the status field of
each resource as appropriate. For example, the controller might download the image, extract the file at the specified path, and add
that file's data to a status field:

```yaml
apiVersion: example.io/v1alpha1
kind: ImageTrustSource
metadata:
  name: example
spec:
  image: docker.io/library/debian:bookworm
  path: /etc/ssl/certs/ca-certificates.crt
status:
  bundleData: |
    -----BEGIN CERTIFICATE-----
    MIID...
    -----END CERTIFICATE-----
```

The bundle data from the source would then be fed into the trust-manager target, in a similar way to how the existing sources are used.

## Open Questions

- If the source plugins need a separate controller, why should that controller not simply write its data into a ConfigMap or Secret, which trust-manager can then consume natively?
  - Concretely: What do we gain from having CRDs here?
  - Does this make setup difficult? Plugin CRDs should be able to be installed before trust-manager.
- Does this require every plugin to bind a role with CRD read permissions to the trust-manager service account?
- Does the key from the status field need to be configurable? Most likely it does - how do we configure it?
