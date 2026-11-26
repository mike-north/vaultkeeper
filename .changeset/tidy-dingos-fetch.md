---
'vaultkeeper': patch
---

Keep substituted credentials out of delegated fetch response metadata. The response and its clones omit the transport URL, headers, and reason phrase while preserving the body stream, numeric status, and redirect flag.

Delayed body reads remain available, and responses retain statuses that native Fetch accepts outside the `Response` constructor's range.

A retained body stream stays readable after its response is collected, even after `response.clone()`. Abandoning all readers and clones of an unread response allows Node to release its connection.
