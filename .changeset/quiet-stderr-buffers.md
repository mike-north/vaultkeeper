---
'vaultkeeper': patch
---

Clear subprocess stdout and stderr buffers after decoding to reduce retention of sensitive output, while preserving UTF-8 characters split across chunks.
