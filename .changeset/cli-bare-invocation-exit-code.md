---
'@vaultkeeper/cli': patch
---

Make a bare `vaultkeeper` invocation exit `2` instead of `0`.

Running `vaultkeeper` with no subcommand previously printed help to stdout and exited `0`, which let `vaultkeeper && next_step` proceed as if a command had succeeded. A bare invocation is a bad invocation (like an unknown command), so it now prints usage to stderr and exits `2`. An explicit `vaultkeeper --help` / `-h` is still a successful usage request and exits `0` on stdout.

This completes the CLI exit-code convention: `0` success, `1` a valid invocation that failed at runtime, `2` a bad invocation (usage / argument-validation error). Empty-stdin `store` already exits `2`.
