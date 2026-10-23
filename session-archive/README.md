# Session archives

Two sanitized omp session archives are committed here instead of being published as releases.

| File | Session | Contents |
| --- | --- | --- |
| `omp-archive-2026-10-09T06-16-19-419Z_01a11f4e-2cdb-70de-98ce-63fc3c7e27b6.zip` | `01a11f4e-2cdb-70de-98ce-63fc3c7e27b6` — "Reverse engineer Dell Optimizer battery charge functions" | Main transcript, manifest, completed-job metadata |
| `omp-session.zip` | `01a1696d-677c-72cb-a949-d9eae050c5a2` — "Dell: Check Dell Optimizer RE compatibility" | Main transcript, artifact/tool logs, manifest, jobs, redaction notes |

Each zip has a matching `.sha256`. Provenance and redaction details are inside the zips
(`README.md`, `SANITIZATION.md`/`REDACTIONS.md`) and in [omp-session.md](omp-session.md).

Both were produced with the
[`omp-archive`](https://github.com/alosslessdev/omp-archive-main) plugin, then sanitized: no secrets,
no absolute home paths, no proprietary binaries or decompiled-source excerpts.
