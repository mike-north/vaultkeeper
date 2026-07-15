---
'vaultkeeper': minor
---

`FilesystemError` now preserves the underlying Node.js filesystem failure it wraps. A new `readonly code: string | undefined` property exposes the original errno code (e.g. `EACCES`, `ENOSPC`, `EISDIR`) so callers can discriminate the failure kind without parsing the message text, and the original error is now recorded as the standard `Error.cause`. The two near-duplicate internal helpers that built `FilesystemError` (one in the file backend, one in the shared at-rest key-wrapping module) have been merged into a single shared helper so this population happens in one place.
