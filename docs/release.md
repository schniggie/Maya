# Releasing Maya

Publishing runs when a semver tag is pushed. Merging a pull request to `main` does not build an image, push to GHCR, or open a GitHub Release.

## Cut a release

On the commit that should ship (normally the current `main`):

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Example:

```bash
git tag v1.2.3 && git push origin v1.2.3
```

That push runs [`.github/workflows/release.yml`](../.github/workflows/release.yml). The workflow checks out the tag, builds the existing sandbox image, pushes it to GHCR, and opens a published GitHub Release with auto-generated notes. It does not create the git tag. Create the tag locally and push it.

The tag must be `vX.Y.Z` (for example `v1.2.3`). Prerelease tags such as `v1.2.3-rc.1` match the workflow filter and then fail before anything is pushed.

## Where the image lands

The image name is lowercase `ghcr.io/schniggie/maya`. Pushing `v1.2.3` publishes:

| Reference | When it moves |
|-----------|----------------|
| `ghcr.io/schniggie/maya:1.2.3` | Stays on this release |
| `ghcr.io/schniggie/maya:1.2` | Moves when another `v1.2.Z` tag is pushed |
| `ghcr.io/schniggie/maya:latest` | Moves when any `vX.Y.Z` tag is pushed |

The Docker build uses the repository root as its context and `containers/Dockerfile.sandbox` as its Dockerfile, the same inputs as the `Docker Build Test` job. The published platform is `linux/amd64`. The workflow logs in to GHCR with the built-in `GITHUB_TOKEN`.

A manual run (`workflow_dispatch`, input `tag`) rebuilds an existing `vX.Y.Z` tag and pushes `:X.Y.Z` and `:X.Y`. It does not move `:latest` and does not open a GitHub Release. Re-run the original tag workflow to publish `:latest` again.

## Pull the image

```bash
docker pull ghcr.io/schniggie/maya:1.2.3
docker pull ghcr.io/schniggie/maya:latest
```

The first push creates the GHCR package. GitHub keeps a new package private until an owner changes its visibility in the package settings.
