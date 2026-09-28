import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import process from "node:process";

const [consumerDirectory, packageName, tarballPath] = process.argv.slice(2);

if (!consumerDirectory || !packageName || !tarballPath) {
  throw new Error(
    "Usage: refresh-consumer-lock.mjs <consumer-directory> <package-name> <tarball-path>"
  );
}

const packageJsonPath = join(consumerDirectory, "package.json");
const packageLockPath = join(consumerDirectory, "package-lock.json");
const fixtureManifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
const sourceManifest = JSON.parse(await readFile("package.json", "utf8"));
const sourceLock = JSON.parse(await readFile("package-lock.json", "utf8"));
const packageEntryPath = join("node_modules", packageName);
const expectedTarball = `file:udid-tools-${packageName.split("/").at(-1)}.tgz`;

if (fixtureManifest.dependencies?.[packageName] !== expectedTarball) {
  throw new Error(`Consumer fixture must depend on ${packageName} through ${expectedTarball}.`);
}

const packageLock = JSON.parse(await readFile(packageLockPath, "utf8"));

if (!packageLock.packages?.[packageEntryPath]) {
  throw new Error(`Consumer lockfile is missing ${packageEntryPath}.`);
}

const sourcePackages = sourceLock.packages;

if (!sourcePackages) {
  throw new Error("Source lockfile has no packages map.");
}

const resolvePackagePath = (parentPath, dependencyName) => {
  let searchPath = parentPath;

  while (searchPath) {
    const nestedPath = join(searchPath, "node_modules", dependencyName);

    if (sourcePackages[nestedPath]) {
      return nestedPath;
    }

    const parentNodeModulesIndex = searchPath.lastIndexOf("/node_modules/");
    searchPath = parentNodeModulesIndex === -1 ? "" : searchPath.slice(0, parentNodeModulesIndex);
  }

  const rootPath = join("node_modules", dependencyName);

  if (!sourcePackages[rootPath]) {
    throw new Error(`Source lockfile is missing ${dependencyName}.`);
  }

  return rootPath;
};

const runtimePackages = {};
const collectRuntimeDependencies = (parentPath, dependencies = {}) => {
  for (const dependencyName of Object.keys(dependencies)) {
    const dependencyPath = resolvePackagePath(parentPath, dependencyName);

    if (runtimePackages[dependencyPath]) {
      continue;
    }

    const dependency = sourcePackages[dependencyPath];
    runtimePackages[dependencyPath] = dependency;
    collectRuntimeDependencies(dependencyPath, dependency.dependencies);
    collectRuntimeDependencies(dependencyPath, dependency.optionalDependencies);
  }
};

collectRuntimeDependencies("", sourceManifest.dependencies);

const sourcePackageEntry = sourcePackages[""];
const consumerPackageEntry = {
  version: sourceManifest.version,
  resolved: expectedTarball,
  integrity: `sha512-${createHash("sha512")
    .update(await readFile(tarballPath))
    .digest("base64")}`,
};

for (const field of [
  "bin",
  "cpu",
  "dependencies",
  "engines",
  "hasInstallScript",
  "license",
  "optionalDependencies",
  "os",
  "peerDependencies",
  "peerDependenciesMeta",
]) {
  if (sourcePackageEntry[field] !== undefined) {
    consumerPackageEntry[field] = sourcePackageEntry[field];
  }
}

packageLock.packages = {
  "": packageLock.packages[""],
  [packageEntryPath]: consumerPackageEntry,
  ...runtimePackages,
};
await writeFile(packageLockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
