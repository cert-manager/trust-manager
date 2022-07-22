# Design: Static Public Trust Bundles

- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [User Stories](#user-stories)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Bundle Container Server](#bundle-container-server)
  - [Behaviour After Consumption](#behaviour-after-consumption)
  - [Test Plan](#test-plan)
  - [Graduation Criteria](#graduation-criteria)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
  - [Supported Versions](#supported-versions)
- [Production Readiness](#production-readiness)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be
merged.

- [ ] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented
- [ ] Feature gate status has been agreed upon (whether the new functionality will be placed behind a feature gate or not)
- [ ] Graduation criteria is in place if required (if the new functionality is placed behind a feature gate, how will it graduate between stages)
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website]

## Summary

Most programs, programming languages and libraries consume their trust bundles from a standard
location on-disk. On Linux, the standard bundle is typically provided by the distribution. The same
applies to containers, in which the base image used is often the provider of a standard TLS trust bundle.

Currently, `trust-manager` makes it easy to construct a bundle in a mechanical sense, but doesn't really
help in choosing / collecting the various parts which actually go into a bundle. For private or
organization-specific CAs, there's only a limited amount which trust-manager can do, but for public
bundles - such as those mentioned above used by Linux distros - there's a role that trust-manager can play
by providing a bundle for people to consume.

We propose that we should start helping in what is likely the most common case: to add an option
for a "public" trust bundle as a source, which should be as easy to consume as possible.

## Motivation

The ideal situation for the vast majority of applications is likely to be that they don't have to
explicitly configure their application's trust bundle.

By way of example, a Linux Golang application would [currently](https://github.com/golang/go/blob/2d655fb15a50036547a6bf8f77608aab9fb31368/src/crypto/x509/root_linux.go#L8-L15)
look in the following locations by default:

```go
var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}
```

It's a chore to manually specify a location for a trust store, and it's unfamiliar and error-prone
for many users. However, if a user instead overwrites any of these files with their own
trust-manager-generated certificate trust bundle they'll currently overwrite their public trust bundle
provided by their OS / container base image.

Unless the user's application only talks to services which the user also controls, what users are
likely to really want in most cases is a bundle containing both the publicly trusted certs _and_
the user's own roots.

It's possible in most distros to append to the cert bundle, but that usually involves running some
command to generate the final bundle, which would change how the user invokes their application
inside their container.

Ideally, the whole bundle a user requires would simply be available at one of the above locations.

In Kubernetes, that today likely means overwriting the system trust bundle with an entire bundle
at the point when the container is created. That implies that the Target which trust-manager creates
must be completed before the container starts, and that in turn implies a need for the public
trust bundles users rely on to be available as sources for trust-manager.

### Goals

- A user configuring a `Bundle` can add a public trust bundle at least as easily as they can add certs from a `ConfigMap` or `Secret`
- It's clear to users exactly what version of the public bundle is used at any given time, for auditing purposes
- A user whose application must use both public and private CAs can confidently overwrite their "system" trust store in a container using a trust `Bundle`
- A user can update any bundle in use with any version of the trust-manager controller and be confident that it will work

### Non-Goals

- Editing/pruning the public trust bundle (out of scope for the initial feature but might be desirable later)
- Supporting [OS-specific](https://superuser.com/questions/437330/how-do-you-add-a-certificate-authority-ca-to-ubuntu) certificate update mechanisms
- Supporting a plethora of options for sources of public trust bundles; we might want this in the future but we should start with one
- Dynamically updating the public bundle (users will have to explicitly choose to upgrade, at least for now)

## Proposal

We propose that the cert-manager project becomes a distributor of its own public trust bundle, which at
least to start will be a carbon copy of the Debian `ca-certificates` package.

That bundle in will in turn be packaged into a container which will be used as an init container in the
trust-manager controller's pod, with the ability to present its bundle to the controller container.

To disambiguate between "public trust bundles" and the trust-manager "Bundle" resource, we'll call
the cert-manager project's public trust bundles "packages" instead.

In the initial implementation of this feature, users will pass the location of a single JSON-formatted
package to the trust-manager controller at startup. If given, this package must load successfully
and have a nonzero number of valid certificates in it. For most users who use Helm, they'll not have
to worry about this since the default trust package will be configured entirely in Helm.

This single package then becomes the "default CA package", and it remains static for the lifetime of the
trust-manager controller pod.

In order to refer to the default package in a Bundle, we'll also add a new boolean source for
requesting the package.

```yaml
apiVersion: trust.cert-manager.io/v1alpha1
kind: Bundle
metadata:
  name: my-org.com
spec:
  sources:
  - configMap:
      name: "my-root-cm"
      key: "root-cert.pem"
  - useDefaultCAs: true
  target:
    ...
```

### Workflow Example

1. The trust-manager pod starts with an init container: the `cert-manager-package-debian` container, which simply copies its JSON file to a predefined location and then exits.
2. The copied package JSON looks like this:

    ```json
    {
      "name": "cert-manager-debian",
      "bundle": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n...",
      "version": "<VERSION>.0"
    }
    ```

3. The trust-manager controller starts, this time with a new argument: `--default-package-location=/path/to/package-cert-manager-debian.json`
4. During startup, the controller validates the package and if succesful loads its `bundle` into memory for later use as the "default package".
5. When a `Bundle` resource requests to `useDefaultCAs`, the `bundle` field from the default package is inserted into the target.

### User Stories

#### Story 1: Standard Platform Deployment

Alice is a platform engineer using trust to ensure that the same trust bundle is present across all
of the pods in her cluster.

She upgrades to a new version of trust which supports the bundle container. The Helm chart points
to a default version of the bundle which was set at the time the version of trust was released, and
she's happy with the defaults.

After rolling out the upgrade she edits her `Bundle` resources to `useDefaultCAs`. She kicks off
a fresh deployment of all pods and now they all have all the certificates she needs to talk to both
public services and services using her organization's private CA.

#### Story 2: Security Incident

Bob is a security engineer responding to a major security incident involving a root certificate
whose private key was exposed on the internet.

For each cluster in which trust-manager is deployed Bob updates the Helm `defaultPackageImage.tag` variable
to point to the latest version of the bundle container. He then proceeds to roll out the bundle much
as Alice did above - by rolling the deployments of each service. The vulnerability is patched safely.

#### Story 3: Security Incident Without Packages

(This story is intended to illustrate the problems an engineer would have today if trying to deal with
a root CA private key being exposed)

Charles is a security engineer responding to the same incident as in Story 2, but without already using
trust-manager inside his clusters.

He has to update the base image of every container the organisation builds to remove the compromised root,
but that task requires several steps:

1. Ensuring he has a list of every base image used across the organization. If he misses a container,
   it'll be vulnerable to MitM attacks until it's updated.
2. Making sure that each distinct base image used across the organization (Alpine / Debian / Distroless / etc)
   has actually received the updated trust store. There's no point updating if there's nothing to update to!
3. Rebuilding every single container which has an embedded trust bundle across the organization. In practice,
   this is nearly all of them.
4. Testing the newly built containers in CI to ensure that the updated base images haven't changed any other
   functionality. If some containers were running an out-of-support base image, they won't get the updated
   ca-certificates package, and Charles might need to bump to a new minor version which could be incompatible
   with his applications.
5. After rebuilding, he has to roll all deployments of all pods to make sure they're using the new images.

### Risks and Mitigations

#### Bundle Container Updates

This proposal makes it absolutely critical that we have a smooth and rapid release process for the
"package" container. A security incident involving a root certificate would be front-page news and a
major incident for basically every organisation in the world and we'd have to treat it the same,
to the point of waking engineers up in the middle of the night to cut a new release if required.

Likewise, it's important that the package is validated during the build, to ensure it'll be usable.

#### Bundle Container Attack Surface

Since this proposal includes a need for some kind of process by which the controller container can
query the bundle from the bundle container, that necessitates an increase in the attack surface of
trust-manager as an overall application.

The communication channel between the controller and bundle containers is absolutely security critical;
if a malicious actor were able to intercept and modify the bundle in-flight it would allow them to insert
their own root certificate and MitM every connection between any container using the resulting bundle.

This is mitigated by the use of two containers in a Pod - the Kubernetes security model should allow
for this to be done securely without interference. Ultimately any design is likely to come down to
sharing files, and if we can't securely share files between our containers then any reasonable threat
model would break down anyway.

## Design Details

### Test Plan

End-to-end tests should be written which use public bundles in a trust object, and ensure that the
bundle is correctly inserted into the output.

### Upgrade / Downgrade Strategy

For an implementation of this design to be acceptable, it should ensure that it's _always_ trivial to
upgrade and downgrade between versions of the bundle container. That implies that the API between
the bundle container and trust container should be absolutely ironclad with regards to backwards
compatibility.

In this design, the bundle is kept as simple as possible by having it be a field ("bundle") in a JSON
file. As long as future versions of trust-manager are able to read JSON files, the data should be available.

## Alternatives

### Bundling Packages Into trust-manager

The obvious alternative here is that the public trust bundle be embedded into trust-manager itself.

This makes the architecture simpler, but might introduce issues when it comes to upgrading and downgrading.

Assuming that we'll presumably end up in a similar situation with trust-manager as we have in cert-manager,
where we support a subset of available `trust-manager` versions with updates while deprecating others, we have
to consider the upgrade path for trust packages in an emergency.

If there's a compromise of a publicly trusted root, it's likely to be one of the most consequential
computer security incidents ever and everyone will scramble to update immediately.

That scramble should be made as easy as possible. It's likely not feasible for us to update trust
bundles baked into every release of trust itself, so it's easier to separate that upgrade path out.

Having the public bundle be a separate component also helps us to develop mechanisms by which it
can be easily updated. For example, we could add an auto-updater version of the bundle container
which would pull an updated version automatically, allowing cluster operators to choose to opt-in
to automatic updates if they so desire.

### Just Doing Nothing

See "Motivation" above. There is a _very_ clear need for this kind of functionality.

## Future Work: Dynamic Bundles

It's possible to envision a potential future bundle type which dynamically updates, perhaps in response
to querying an HTTP server for an update bundle at runtime. This would allow for faster updates, and
would presumably involve running a sidecar container rather than an init container.

Rather than try to solve this issue now, we'll defer this to a future feature.

### Links

It's worth taking a look at the sources for Debian's [ca-certificates package](https://salsa.debian.org/debian/ca-certificates/-/tree/master/)
and [Fedora's equivalent](https://src.fedoraproject.org/rpms/ca-certificates), as background on
how popular Linux distributions package their default certificate bundles.
