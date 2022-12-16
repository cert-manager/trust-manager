# `cert-manager-package-debian` Trust Package

For details on what trust packages are, see the [trust-packages README](../README.md).

This trust package uses a Debian container to retrieve its trust package. Debian was chosen
to be the first source for trust packages as it's also used as the base for the [distroless base images](https://github.com/GoogleContainerTools/distroless)
which are used in the cert-manager project.

Therefore, by using Debian again here, we're not adding any new entities we need to trust, since we already trust
Debian extensively elsewhere.
