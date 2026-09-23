# Locked consumer smoke test

CI and the release workflow copy the exact `npm pack` artifact into this fixture as
`udid-tools-core.tgz`, then run `npm ci`. The committed lockfile pins both the tarball integrity
and its complete runtime dependency tree, so the smoke test cannot resolve newer transitive
packages during a build or release.

When a change alters the packed artifact, rebuild it, temporarily place it at
`tests/consumer-smoke/udid-tools-core.tgz`, and regenerate the lockfile with lifecycle scripts
disabled. Never commit the tarball.
