# Version v1alpha2 API changes

In v1alpha2, `ClusterBundle` was introduced as a replacement for v1alpha1 `Bundle`.
This was mainly done to make room for a future namespace-scoped `Bundle`.
But with this opportunity to improve the API, this highlights the changes to the API.

## Target API changes

- The `namespaceSelector` for namespaced target resources is now a mandatory field.
  Previous default behavior of syncing to all namespaces can be achieved by setting an
  empty selector: `namespaceSelector: {}`.
- The PKCS#12 trust store default profile has changed from `LegacyRC2` to `LegacyDES`,
  which is the profile with maximal compatibility (also supported by OpenSSL 3 or Java version > 20).
- The deprecated JKS trust store format has been removed.
- The structure of the target specification has changed, but any v1alpha1 target spec is still
  possible in v1alpha2. The new target spec supports use-cases that were not possible in v1alpha2:
  - Multiple target resource keys of the same format. This could be useful for migration or when
    consuming software mandates resources with specific keys (`cert`, `crt.pem`, etc.).
  - Different form on target configmaps and secrets for "additional formats" (JKS/PKCS#12).
    In v1alpha1 the `target.additionalFormats` would always apply to both configmaps and secrets.

## Future opportunities with the new API

The API was changed to simplify trust-manager internals like validation, but also to make room
for new features we want to implement like:

- Integration with [Kubernetes `ClusterTrustBundle`](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles),
  which doesn't support JKS or PKCS#12 and also might impose some target naming constraints.
