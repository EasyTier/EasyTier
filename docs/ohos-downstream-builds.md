# HarmonyOS HAR delivery

The `ohos` workflow builds the Core HAR on pushes, pull requests, tags, and
manual runs. Every successful run retains a short-lived HAR artifact, while
publication to the private OHPM registry is deliberately restricted:

- A push to `main` publishes only when the pushed SHA is the merge commit of a
  pull request targeting `main` and the push is not forced.
- A manual run on `main` publishes by default.
- A manual run on another branch publishes only when its `publish` input is
  enabled.
- Direct pushes, pull requests, tags, and ordinary non-main branch builds do
  not publish.

## Package identity

All branches publish the same private package name, `easytier-ohrs`. The
source branch is encoded in the package version instead of the package name:

```text
<core-version>-<branch-id>-<commits-since-tag>-<run-number>-<run-attempt>-g<short-sha>
```

`branch-id` is a lowercase, OHPM-safe form of the source branch. Publishing a
new version advances the registry's `latest` version. After publication, Core
sends the `core-har-published` repository dispatch to the ArkTS and Pro
repositories. The payload contains only `core_repository`, `core_ref`, and
`package_name`.

## App install sequence

ArkTS and Pro use the same three OHPM commands:

```bash
ohpm uninstall "$CORE_HAR_PACKAGE"
ohpm install "$CORE_HAR_PACKAGE@latest" \
  --registry "$CORE_HAR_REGISTRY"
ohpm install
```

The App workflow then reads the installed version from:

```text
oh_modules/<package_name>/oh-package.json5
```

The existing `oh-package-lock.json5` and `oh_modules` directory are not
manually deleted. Because the package name remains `easytier-ohrs`, downstream
source imports do not need to be rewritten.

## Secrets

Core requires:

- `CODEARTS_PRIVATE_OHPM`: publish-capable OHPM configuration.
- `DOWNSTREAM_DISPATCH_TOKEN`: permission to dispatch both App repositories.

ArkTS and Pro require:

- `CODEARTS_PRIVATE_OHPM_READ`: read-only private OHPM authentication.
- `SIGNING_REPOSITORY_TOKEN`: read access to the corresponding private signing
  repository.

Signing and AppGallery Connect credentials remain downstream application
concerns and are not passed through the Core dispatch payload.
