# Linux package distribution

Dribik releases include a self-contained `amd64` Debian package built on Ubuntu 24.04. It bundles
the Python runtime dependencies, so a user does not need `pip`, `pipx`, or a development checkout.

## Installing a GitHub Release asset

Download the `.deb` attached to the chosen [GitHub Release](https://github.com/Gmblos/Dribik/releases),
then install it locally:

```bash
sudo apt install ./dribik_<version>_amd64.deb
dribik --version
```

This package is built and smoke-tested automatically whenever a maintainer pushes a `v*` tag.

## Enabling `apt install dribik`

The bare package name works only after an APT repository has been configured. GitHub Releases are
download pages, not APT repositories: they do not publish a signed `Release` file or package index.

To offer `sudo apt install dribik` globally, publish the generated `.deb` files through a signed
APT repository (for example, a self-hosted `aptly` repository, Cloudsmith, or Launchpad) and give
users that repository's signing key and source-list entry. Keep the signing key outside the Git
repository and use a GitHub Actions secret for release signing.
