# Locked consumer smoke test

CI and the release workflow copy the exact `npm pack` artifact into this fixture as
`udid-tools-core.tgz`. They refresh the temporary consumer lockfile from the exact artifact and
the repository's locked runtime dependency tree, then run `npm ci`. This keeps the packed
artifact's integrity and runtime metadata in sync without allowing a build or release to resolve
packages from the registry.

The committed fixture lockfile is a baseline for the runtime dependency tree. CI refreshes the
temporary copy from the exact artifact; never commit the tarball or that temporary lockfile.
