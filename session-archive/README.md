# Session archive

Archive of the omp session that produced this repository's analysis
(`01a11f4e-2cdb-70de-98ce-63fc3c7e27b6`, "Reverse engineer Dell Optimizer battery charge functions").

- `omp-archive-2026-10-09T06-16-19-419Z_01a11f4e-2cdb-70de-98ce-63fc3c7e27b6.zip` — built with the
  [`omp-archive`](../../../../alosslessdev/omp-archive-main) plugin (`--no-artifacts`), then sanitized.
- `*.sha256` — SHA-256 of the zip.

The archive holds the main session transcript (`session.jsonl`, byte-for-byte apart from redactions),
`manifest.json`, derived completed-job metadata, and the notes inside the zip (`README.md`,
`SANITIZATION.md`).

Sanitization: no secrets, no absolute home paths, no proprietary binaries or decompiled-source
excerpts. The 190 MB `artifacts/` tree (untruncated tool logs with bulk decompiled output) was excluded.
See `SANITIZATION.md` inside the zip for the detectors and counts.
