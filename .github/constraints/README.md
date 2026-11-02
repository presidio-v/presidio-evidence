# Hash-pinned release toolchains

These `*.txt` files are `--require-hashes` lockfiles for everything the CI and
release workflows install with `pip`: the standalone tools, and the project's own
extras (the package itself is then installed with `--no-deps`). Pinning by hash satisfies the OpenSSF Scorecard
**Pinned-Dependencies** check and stops a compromised package index from
substituting the build backend, the metadata checker or the SBOM generator.

| File | Tools | Used by |
|---|---|---|
| `ci-toolchain.txt` | pip, setuptools | `ci.yml` (all jobs) |
| `release-build.txt` | pip, build, hatchling | `publish.yml` (build) |
| `twine.txt` | twine | `publish.yml` (metadata check) |
| `cyclonedx.txt` | cyclonedx-bom | `publish.yml` (SBOM) |
| `dev.txt` | the `dev` extra + `editable-backend.in` | `ci.yml` (gate and Python matrix) |
| `fuzz.txt` | the `fuzz` extra + `editable-backend.in` (Python 3.12) | `fuzz.yml` |
| `crypto.txt` | the `crypto` extra | `publish.yml` (runtime environment the SBOM describes) |

## Regenerate

```bash
cd .github/constraints
for base in ci-toolchain release-build twine cyclonedx; do
  uv pip compile --generate-hashes --universal --python-version 3.11 \
    --annotation-style=line "$base.in" -o "$base.txt"
done
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml --extra dev editable-backend.in -o dev.txt
uv pip compile --generate-hashes --universal --python-version 3.12 \
  --annotation-style=line ../../pyproject.toml --extra fuzz editable-backend.in -o fuzz.txt
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml --extra crypto -o crypto.txt
```

Add `--upgrade` to move existing pins to the newest allowed versions (without
it, uv keeps the pins already in the output file). Re-run the extras lines
whenever `[project.optional-dependencies]` in `pyproject.toml` changes; CI
installs only what the lockfile lists, so a missing dependency fails the job.

Bump a tool by editing the matching `*.in` and re-running the loop. Keep the
hatchling range in `release-build.in` in step with `[build-system] requires` in
`pyproject.toml`.
