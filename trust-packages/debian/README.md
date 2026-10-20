# `cert-manager-package-debian` Trust Package

For details on what trust packages are, see the [trust-packages README](../README.md).

This trust package uses a Debian container to retrieve its trust package. Debian was chosen
to be the first source for trust packages as it's also used as the base for the [distroless base images](https://github.com/GoogleContainerTools/distroless)
which are used in the cert-manager project.

Therefore, by using Debian again here, we're not adding any new entities we need to trust, since we already trust
Debian extensively elsewhere.

This package is used for Debian Bookworm and Debian Trixie.

## Removed roots

The bundle we ship is **not** a byte-for-byte copy of Debian's `/etc/ssl/certs/ca-certificates.crt`.
Before the bundle is wrapped in the package JSON, we strip out every root listed in
[`make/config/distrusted-roots.json`](../../make/config/distrusted-roots.json), which is the source of
truth for this. Roots are matched on the SHA-256 fingerprint of their DER encoding, and each entry
carries a `reason` explaining why it's distrusted.

Entries are advisory: a root is removed if it's present and ignored if it isn't. That's deliberate.
Some entries are listed defensively against roots Debian doesn't ship today, and when Debian removes a
listed root itself the entry simply becomes inert rather than breaking the build. The guarantee that's
actually enforced is the stronger and more stable one — that no listed fingerprint appears in the
package we publish — which `validate-trust-package --denylist` checks against the final JSON on every
build.

As of `ca-certificates` 20250419, both the Bookworm and Trixie bundles go from 150 to 148 certificates,
losing `emSign ECC Root CA - G3` (eMudhra) and `AAA Certificate Services` (Sectigo).

### Changing the list means bumping the version suffix

The package version is `<debian ca-certificates version>.<suffix>`, and it's also the OCI image tag.
Editing `distrusted-roots.json` changes the bundle contents *without* changing the Debian version, so
every such change must be accompanied by a manual suffix bump in
[`make/00_debian_bookworm_version.mk`](../../make/00_debian_bookworm_version.mk) and
[`make/00_debian_trixie_version.mk`](../../make/00_debian_trixie_version.mk) (e.g. `20250419.3` →
`20250419.4`). Without it, a new bundle would be published under an already-released tag.

The automated upgrade workflow is unaffected: when Debian publishes a newer base version the suffix
correctly resets to `.0` and the filter re-applies.
