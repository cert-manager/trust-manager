# Design: Renaming Bundle to ClusterBundle

- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Test Plan](#test-plan)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
- [Alternatives](#alternatives)
- [Future Work](#future-work)

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be
merged.

- [ ] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website]

TODO: add more items to checklist

## Summary

We want to rename `Bundle` to `ClusterBundle` for reasons described in "Motivation" below.

Conversion webhooks in Kubernetes can only be used to convert between versions of an API,
and not to convert between resources. This makes renaming harder to do, as it will represent
deleting the old API and creating a new API.

Even though trust-manager `Bundle` API is officially in an alpha state, we want to provide a smooth
migration path for our users. For this reason we are proposing to do this change over multiple releases,
requiring end-user action on the way, but without risking trust-manager target resources - which can provide
critical features in a cluster. For additional details, please see "Proposal" below.

## Motivation

We have [an open issue](https://github.com/cert-manager/trust-manager/issues/63) suggesting renaming Bundle to ClusterBundle.
Might seem like an obvious WontFix, considering all the assumed work (and pain) to do this,
but it turns out that the current name somehow blocks introducing an equivalent namespace-scoped resource -
for trust bundle management inside namespaces in multi-tenant clusters.

In addition, `ClusterBundle` would be a better name looking at cert-manager having `Issuer` and `ClusterIssuer`.
The name would also be better aligned with upstream [ClusterTrustBundle](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles).

### Goals

- `Bundle` resource is renamed to `ClusterBundle`
- Provide a smooth migration for users of trust-manager


### Non-Goals

- Change/fix/improve `Bundle`/`ClusterBundle` API while renaming
- Introduce a new API version
- Introduce a namespace-scoped bundle API (at least not now)

## Proposal

We propose to do this change over multiple releases:

1. Version X: Only `Bundle` API is served and has the functional controller. (present state)
2. Version X+1: We introduce `ClusterBundle` with API otherwise identical to `Bundle`:
   - `Bundle` is marked as deprecated.
   - Functional controller is migrated to `ClusterBundle`
   - Validating webhook for both `Bundle` and `ClusterBundle` with same validations
   - New technical controller added for `Bundle`, converting bundles to cluster bundles
3. Version Y: Remove `Bundle` and only serve `ClusterBundle` (desired state)

Some of these actions/states require extra attention, which are further described below.

### Functional Controller Migration

This should be rather simple. Since the APIs are identical, we just have to perform a "smart"
search and replace in the controller code. When the controller initially boots up on the X+1 version,
there will be no `ClusterBundle` resources in the cluster, as these will be created/updated by the technical
controller.

The `ClusterBundle` reconciler should do the same as for `Bundle` in version X, but we should test/verify that
the controller is able to change owner references on target resources from `Bundle` to `ClusterBundle` without
facing issues.

We must also ensure that the `ClusterBundle` reconciler isn't deleting target resources it thinks are "orphaned".
We believe the controller will only delete target resources if/when the controller resource exists, and
otherwise rely on the Kubernetes garbage collector to delete orphans. But this should be tested/verified.

### Temporary Technical Controller

When the functional controller is migrated to target `ClusterBundle`, we want to introduce a temporary technical
controller targeting the now deprecated `Bundle` resource.

This controller should just create or update the `ClusterBundle` with the same name as the reconciled `Bundle`.
Since the APIs should have identical `spec`, this should be a simple controller.

To allow a user to migrate their resources from `Bundle` to `ClusterBundle`, the controller should not act
on `Bundle` delete events. Nor add an owner reference to `ClusterBundle` to avoid the Kubernetes garbage collector
to act on deletes.

For reconciling a `ClusterBundle` from `Bundle` we should investigate the possibility of "smart field manager name logic".
It should be possible to read the field manager name used (by user) to create/update the `Bundle` resource.
If we use the same field manager name in controller (per resource) to create/update `ClusterBundle`, we think it's less
likely that users will have to force conflicts when migrating from `Bundle` to `ClusterBundle`.

### Risks and Mitigations

#### Target configmaps/secrets are accidentally deleted

Since using owner references in this project, we need to be extra careful when performing changes like this.

We mitigate this risk by **NOT** cascading deletes of `Bundle` to `ClusterBundle`.
This is done by **NOT** adding owner references to `ClusterBundle`, and instead use the resource `name`
to map between `ClusterBundle` and `Bundle` resources.

Owner references on target resources are changed by the reconciler from `Bundle` to `ClusterBundle`,
which means targets could only be deleted if the `ClusterBundle` is deleted or `namespaceSelector`
is changed. This is the expected behavior.

#### Target configmaps/secrets appearing as orphaned

This could happen if a users deletes a `Bundle` resource expecting the target configmaps/secrets
to vanish. Unfortunately this won't happen by the defensive approach taken to not cascade `Bundle`
delete to `ClusterBundle`.

In order to achieve the wanted behavior, a user would have to delete the corresponding `ClusterBundle`,
which appears like a simple workaround that we should document.

## Design Details

### Test Plan

TODO

### Upgrade / Downgrade Strategy

Downgrading from a version where the migration has started will probably not be possible and should
be clearly documented and stated in the release notes.

## Alternatives

### Just rename resource between releases

Since the `Bundle` API version is `v1alpha1`, we could justify just doing the simplest thing and rename.
This approach could cause potentially catastrophic failures in user clusters when the `Bundle` CRD is deleted
since all target configmaps/secrets are owned by bundle and would be deleted by the Kubernetes garbage collector.

### Doing Nothing

See "Motivation" above.

## Future Work

- Introduce a **namespace-scoped** `Bundle` resource.
- Integration with upstream [ClusterTrustBundle API](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles).
- New and improved version of the `ClusterBundle` API
