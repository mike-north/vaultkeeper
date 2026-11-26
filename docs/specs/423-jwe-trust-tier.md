# JWE trust-tier interoperability

The encrypted `tid` claim in newly issued compact JWE tokens is the JSON string
`"1"`, `"2"`, or `"3"`. Both implementations accept these strings and the
integer values 1, 2, and 3 emitted by older TypeScript issuers. Unknown tiers
and other string spellings are rejected. The TypeScript claims API continues
to represent tiers as numbers. Configuration has its own serialization policy.

An older TypeScript reader only accepts numeric tiers. Upgrade those readers
before enabling upgraded issuers, or coordinate the deployment. Existing Rust
readers already accept the canonical string form.
