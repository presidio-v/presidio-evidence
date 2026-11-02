# Hash-pinned release toolchains

These `*.txt` files are `--require-hashes` lockfiles for the standalone tools that
the CI and release workflows install with `pip`. Pinning by hash satisfies the OpenSSF Scorecard
**Pinned-Dependencies** check and stops a compromised package index from
substituting the build backend, the metadata checker or the SBOM generator.

| File | Tools | Used by |
|---|---|---|
| `ci-toolchain.txt` | pip, setuptools | `ci.yml` (all jobs) |
| `release-build.txt` | pip, build, hatchling | `publish.yml` (build) |
| `twine.txt` | twine | `publish.yml` (metadata check) |
| `cyclonedx.txt` | cyclonedx-bom | `publish.yml` (SBOM) |

## Regenerate

```bash
cd .github/constraints
for base in ci-toolchain release-build twine cyclonedx; do
  uv pip compile --generate-hashes --universal --python-version 3.11 \
    --annotation-style=line "$base.in" -o "$base.txt"
done
```

Bump a tool by editing the matching `*.in` and re-running the loop. Keep the
hatchling range in `release-build.in` in step with `[build-system] requires` in
`pyproject.toml`.
