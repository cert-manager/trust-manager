# trust-packages

A trust package (or package) is a container which can be run as an init container, before the trust-manager controller,
which writes a JSON package containing a list of PEM encoded certificates.

trust-manager can then be configured - through a flag on startup - to load a bundle and designate it as the `defaultPackage`,
which in turn can be referred to in `Bundle` resources as a new source.

The main intended use of this feature is to enable easy use of 'public trust bundles', such as the Mozilla bundle which
is packaged into most Linux distributions. The `defaultPackage` source then becomes shorthand for "trust the usual stuff".
