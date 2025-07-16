---
title: Bundle CRD
authors:
  - "@joshvanl"
editor: "@joshvanl"
creation-date: 2021-07-15
last-updated: 2021-07-15
status: implemented
---

# Bundle CRD

## Table of Contents

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
- [Goals](#goals)
  * [Non-Goals](#non-goals)
- [Proposal](#proposal)
  * [Bundle](#bundle)
    + [API](#api)
    + [Custom Cache](#custom-cache)
    + [Upstream CertificateBundle](#upstream-certificatebundle)
  * [Testing](#testing)
  * [Risks and Mitigations](#risks-and-mitigations)
  * [Graduation](#graduation)
      - [Alpha](#alpha)
      - [Beta](#beta)
      - [GA](#ga)
<!-- /toc -->


## Summary

[Bundle](https://github.com/cert-manager/trust-manager/blob/44d8fcaeec7232daf6dd14a1be5a6d0791bc23b8/pkg/apis/trust/v1alpha1/types_bundle.go)
is a cluster scoped CRD designed to distribute trust data across a cluster so
that it is made available by all services that need it. Bundle is intended to be
complementary to [cert-manager](https://github.com/jetstack/cert-manager) by
allowing access to trust data that is either known to cert-manager, or external
to any cert-manager [Issuer](https://cert-manager.io/docs/configuration/).

Bundle sources its data from a trusted namespace. This trusted namespace is the
same namespace that the operator is deployed to, which is typically
`cert-manager`. The sourced data is then concatenated together, and propagated
across the cluster to a target, making it available for consumers.

Bundle is intended to be powerful and flexible enough to meet the use case of
most users who want some set of trust bundle data available for their services.
Trust bundle data doesn't need to be known to the cluster operator before the
cluster is created.

## Motivation

Kubernetes currently has a limited story for distributing trust within a
cluster. While API server CA bundle data is available to all pods at a
well-known
[file location](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/#directly-accessing-the-rest-api)
mounted by the Kubelet at runtime, as well as the
[ConfigMap in all namespaces `kube-root-ca.crt`](https://github.com/kubernetes/kubernetes/pull/100926/files#diff-60eb175dae1dcc1320f5c426f6d193a67e961e2bd96d574f941cdf09672090f6R44),
this bundle data can only be modified via
[API server CLI flags](https://kubernetes.io/docs/setup/best-practices/certificates/).
Modifying these CLI flags to append arbitrary trust bundles is both impossible
for managed Kubernetes users, and is a misuse of its intention. CLI flags are
static, and can't be realistically changed in response to runtime events.

cert-manager exposes a
[`Status.CA` field on CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/),
as well as stores a
[`ca.crt` field in generated Secrets resulting from Certificates](https://cert-manager.io/docs/concepts/certificate/).

These values are however:
- populated on a best-effort basis by the Issuer and not required for successful
  issuance,
- only available after a successful certificate request,
- scoped only to the namespace containing the Secret/CertificateRequest,
- regarded as a controversial inclusion to the cert-manager API because they
  encourage various subtle anti-patterns.

Notably, these fields in practice only ever contain one CA certificate, which
makes their direct use as trust bundles dangerous; without the ability to have
multiple certificates in a trust store, rotation cannot be reliably and safely
carried out without downtime.

The upstream
[Kubernetes CertificateSigningRequest resource](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)
does not include any CA field. This means consumers are forced to,
[and are intended to](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#kubernetes-signers),
find an out of band method of propagating CA data.

Some users have success by baking CA data into built container images.
This however requires the assumption that CA data is: known before runtime, long
lived, and all images that require the CA data are built in house.

Projects such as [Istio](https://istio.io/) (as well as Kubernetes itself) has
had success with distributing trust roots, at runtime, by using a
[well-known ConfigMap `istio-ca-root-cert`](https://istio.io/latest/docs/tasks/security/cert-management/plugin-ca-cert/)
that is available within every namespace in a cluster. Bundle is an extension of
this idea- to allow users to use the same approach with a resource that is
expressive enough to meet most needs.

## Goals

- Create a `Bundle` resource to distribute trust bundles to be made available to
    all services that need them.
- Assist and help investigate
  [upstream](https://github.com/kubernetes/kubernetes/issues/63726) the best
  solution for trust distribution in Kubernetes.
- Enable _most_ users to effectively distribute trust data in their clusters.
- Bundle should provide _both_ clients and servers with the trust data they need
    to communicate.


### Non-Goals
- Enable _every_ user's use case.
- Compete with upstream development.
- Provide tooling or automation for _consumers_ of distributed trust data to
    update their local trust stores if the trust data changes. Cluster operators
    are advised to:
    - use applications that watch for local file/resource changes and update
      their trust stores accordingly,
    - run sidecars that automate or manually perform a rolling restart when a
        change occurs.

## Proposal

### Bundle

A single resource `Bundle` within the `trust.cert-manager.io` group makes up
the trust operator. This resource fetches and appends data from a number of
`sources` in the trust namespace, and distributes them to a `target`.

The trust namespace is the same namespace that the trust operator is deployed
to, which would normally be the `cert-manager` namespace.

While sources currently support `ConfigMap`, `Secret` and `InLine`, it could be
extended to other resources in future, or even remote servers in the aid of
custom informers.

Similarly, target only supports `ConfigMap` but can be extended to other
resources or backends in future.

Each input source data (which is typically a certificate), has white space
trimmed from the prefix and suffix, and are concatenated into a final bundle
with new lines (`\n`). Bundle _will not_ remove any comments or other text form
the resulting data bundle.

#### API

```golang
// BundleSepc defines the desired state of a Bundle.
type BundleSpec struct {
	// Sources is a set of references to data whose data will sync to the target.
	Sources []BundleSource `json:"sources"`

	// Target is the target location in all namespaces to sync source data to.
	Target BundleTarget `json:"target"`
}

// BundleSource is the set of sources whose data will be appended and synced to
// the BundleTarget in all Namespaces.
type BundleSource struct {
	// ConfigMap is a reference to a ConfigMap's `data` key, in the trust
	// Namespace.
	// +optional
	ConfigMap *SourceObjectKeySelector `json:"configMap,omitempty"`

	// Secret is a reference to a Secrets's `data` key, in the trust
	// Namespace.
	// +optional
	Secret *SourceObjectKeySelector `json:"secret,omitempty"`

	// InLine is a simple string to append as the source data.
	// +optional
	InLine *string `json:"inLine,omitempty"`
}

// BundleTarget is the target resource that the Bundle will sync all source
// data to.
type BundleTarget struct {
	// ConfigMap is the target ConfigMap in all Namespaces that all Bundle source
	// data will be synced to.
	ConfigMap *KeySelector `json:"configMap,omitempty"`
}

// SourceObjectKeySelector is a reference to a source object and its `data` key
// in the trust Namespace.
type SourceObjectKeySelector struct {
	// Name is the name of the source object in the trust Namespace.
	Name string `json:"name"`

	// KeySelector is the key of the entry in the objects' `data` field to be
	// referenced.
	KeySelector `json:",inline"`
}

// KeySelector is a reference to a key for some map data object.
type KeySelector struct {
	// Key is the key of the entry in the object's `data` field to be used.
	Key string `json:"key"`
}

// BundleStatus defines the observed state of the Bundle.
type BundleStatus struct {
	// Target is the current Target that the Bundle is attempting or has
	// completed syncing the source data to.
	// +optional
	Target *BundleTarget `json:"target"`

	// List of status conditions to indicate the status of the Bundle.
	// Known condition types are `Bundle`.
	// +optional
	Conditions []BundleCondition `json:"conditions,omitempty"`
}
```


#### Custom Cache

To reduce the trust operator permissions and follow the least privileged principle, a
[custom cache](https://github.com/cert-manager/trust-manager/blob/44d8fcaeec7232daf6dd14a1be5a6d0791bc23b8/pkg/bundle/internal/cache.go)
is used. This custom cache allows the controller to watch only source Secrets
within the trust namespace, whilst allowing for example watches on both source
and target ConfigMaps in all namespaces.

An ObjectMeta only watch is used on both
[ConfigMaps and Secrets](https://github.com/cert-manager/trust-manager/blob/44d8fcaeec7232daf6dd14a1be5a6d0791bc23b8/pkg/bundle/controller.go)
in an effort to massively reduce the memory overhead on watching and caching
these resources within informers.

#### Upstream CertificateBundle

There is currently an
[issue open](https://github.com/kubernetes/kubernetes/issues/63726)
in Kubernetes to design and implement a configurable and flexible trust
distribution mechanism. Whilst there is clearly interest in this feature, it is
currently in `backlog`. Bundle has the opportunity to experiment and contribute
guidance upstream about how that feature should be shaped.

Whether Bundle would be superseded or not by some upstream feature, one
suggestion included the addition of the resource `CertificateBundle`. This could
an example of another `BundleTarget` added at a later version.

```golang
type CertificateBundle struct {
  // Certificates is an array of DER encoded certificates that make up the bundle.
  Certificates [][]byte
}
```

### Testing

Unit testing has been used throughout the project. The
[controller-runtime envtest](https://cluster-api.sigs.k8s.io/developer/testing.html#envtest)
library has been used as integration testing for the bundle controller. A smoke
test is included to ensure a full installation and usage of the operator is
successful against a live [Kubernetes Kind cluster](https://kind.sigs.k8s.io/).


### Risks and Mitigations

Since Bundle handles the core trust root data for the cluster, it is paramount
that access to this resource is properly restricted by cluster operators from
all users and ServiceAccounts. Access to this resource should only be granted by
the most privileged of the cluster.

If an attacker were able to modify the Bundle resource (or a generated target
ConfigMap) they could insert their own CA certificate. This would theoretically
enable nearly silent man-in-the-middle attacks against any service which
consumes the trust bundle.

An alternative attack would be to remove source datafrom the bundle, resulting
in an effective DDoS attack for anything which relied on the bundle.

Having read access to Bundles is largely fine, so long as there are no privacy
concerns to exposing the data source locations. Unauthorized write access to
Bundles has catastrophic security implications and should be closely guarded in
audit.

### Graduation

##### Alpha
- Creation of `Bundle` resource.
- Allow a user to specify a set of sources from `ConfigMap`, `Secret`, and
    `InLine` originating from a trust namespace.
- Sync and append those sources to a `Target` so they are made available to all
    services that need them.

##### Beta
- Trust namespace, sources, and target are validated as appropriate
    abstractions.
- Extended the sources and target set so that most user's use cases are
    accounted for.

##### GA
- Migrate or complement a solution made in upstream Kubernetes.
- A wide adoption and validation of the solution by trust distribution users in
    Kubernetes.
