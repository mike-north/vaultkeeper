---
'@vaultkeeper/cli': patch
---

Make `--version` discoverable and accept the commonly-guessed `-v`.

`vaultkeeper --version` already worked, but the top-level `--help` "Global options" block listed only `--config-dir`, so the version flag was findable only by guessing, and `-v` errored as an unknown flag. `--help` now lists `--version` (and `-h, --help`) under Global options, and `-v` is wired to the same version output as `-V`.

A bare `vaultkeeper` invocation with no arguments now renders that same full help on stdout and exits `0` — it prints the identical text `--help` does, so it is a help request, not a usage error. Genuine misuse (unknown command/flag, missing required argument, empty-stdin `store`) still exits `2`.
