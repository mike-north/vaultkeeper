---
"vaultkeeper": minor
---

sign() now throws a typed InvalidKeyMaterialError (instead of a raw OpenSSL decoder error) when the stored secret is not valid PEM/DER private key material; delegatedFetch() now wraps network failures in a typed FetchError instead of letting the raw fetch() rejection escape
