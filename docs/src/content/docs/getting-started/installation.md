---
title: Installation
description: Install the UDID Tools Core beta from npm.
---

Install the public beta from npm:

```bash
npm install @udid-tools/core@beta
```

The beta requires Node.js 22.14 or newer and is designed for trusted server-side environments. Do not bundle signing identities into browser code.

## Runtime contract

The package is ESM-only, framework-agnostic, and performs no filesystem, environment, logging, or network operations on its own.

## GitHub Packages

The same scoped package is published to GitHub Packages. Configure your application—not this repository—with:

```ini
@udid-tools:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

Then install normally. The release pipeline builds one tarball and verifies its checksum before sending that identical artifact to both registries.

## TypeScript and modules

Use NodeNext-compatible ESM or another toolchain that consumes standard ESM declarations:

```json
{
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true
  }
}
```

The package has one public entry point: `@udid-tools/core`. Importing undocumented internal paths is unsupported.
