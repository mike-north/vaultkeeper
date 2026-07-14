---
'@vaultkeeper/cli': minor
---

`vaultkeeper exec` can now run non-interactively. A caller already recorded in the TOFU trust manifest (via `approve` or a prior approval) runs without any prompt on a TTY or not. A new explicit opt-in — the `--yes` flag and the `VAULTKEEPER_YES=1` environment variable — approves an untrusted caller for a single invocation without prompting, recording the approval the same way an interactive `y` would. Without trust and without `--yes`, an untrusted caller on non-TTY stdin still fails, but the error now tells you exactly how to proceed (`vaultkeeper approve --script <caller>` or `--yes`). `exec --help` documents the TTY requirement and both escape hatches, and the README gains a "Running in CI" note. A caller whose contents changed since approval is never auto-approved by `--yes`; it must be re-approved with `vaultkeeper approve`.
