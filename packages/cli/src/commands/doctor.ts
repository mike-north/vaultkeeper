import { parseArgs } from 'node:util'
import { VaultKeeper, defaultBackendType } from 'vaultkeeper'
import { formatError, formatPreflightConfigError } from '../output.js'
import { CONFIG_DIR_HELP_OPTION, CONFIG_DIR_HELP_ENV } from '../config-dir.js'
import { configFileExists, noConfigMessage } from '../config-status.js'

function printDoctorHelp(): void {
  process.stdout.write(
    'Usage: vaultkeeper doctor\n\n' +
      'Run preflight checks to verify the vault is correctly configured\n' +
      'and all required dependencies are available.\n\n' +
      'Options:\n' +
      CONFIG_DIR_HELP_OPTION +
      '  -h, --help   Show this help message\n\n' +
      'Environment variables:\n' +
      CONFIG_DIR_HELP_ENV,
  )
}

export async function doctorCommand(args: string[], configDir: string): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    printDoctorHelp()
    return 0
  }

  // doctor takes no flags of its own (--config-dir is stripped by bin.ts
  // before dispatch). Previously any unrecognized flag was silently
  // ignored — `doctor --bogus` ran the real checks and could exit 0
  // (regression: issue #69) instead of failing as a usage error.
  try {
    parseArgs({ args, strict: true })
  } catch (err) {
    if (err instanceof Error) {
      process.stderr.write(`Error: ${err.message}\n`)
    }
    process.stderr.write('Usage: vaultkeeper doctor\n')
    return 2
  }

  try {
    // Scope checks to the config under configDir: runDoctor loads and
    // validates it itself (via `configDir`), so a present-but-invalid config
    // file surfaces as a failing "config" check rather than being silently
    // skipped or crashing doctor outright (issue #68).
    // The no-config advisory is only shown when we can positively determine
    // the file is absent. When `configFileExists` cannot tell — e.g. the
    // config dir is unreadable (chmod-000), so `fs.access` fails with
    // EACCES/EPERM rather than ENOENT — do NOT abort here (issue #169): let
    // `VaultKeeper.doctor` load the config so the read failure surfaces as a
    // failing `config` check (like a parse error does) instead of crashing
    // before any check renders. `loadConfig` wraps that read error as a
    // typed FilesystemError, which the runner records on the check.
    let configPresent = true
    try {
      configPresent = await configFileExists(configDir)
    } catch {
      configPresent = true
    }
    if (!configPresent) {
      process.stderr.write(noConfigMessage(defaultBackendType()))
    }
    const result = await VaultKeeper.doctor({ configDir })

    // A check that is not required for the active/configured backend(s)
    // (e.g. `ykman`/`op` when no plugin backend is enabled) is informational,
    // not a failure — rendering it with a ✗ alongside genuine failures made a
    // safe, file-default first run look broken (issue #116). Checks that are
    // both optional and unsatisfied are left out of the pass/fail list; they
    // still surface, without the failure icon, in the "Warnings" section
    // below — that's the visual separation between "checks for your active
    // backend" and "optional plugin backends (not configured)".
    const primaryChecks = result.checks.filter((check) => check.required || check.status === 'ok')

    // A check carrying structured `error` context (currently only the
    // `config` check on an invalid config file) renders a brief inline pointer
    // here — never the library's `reason` prose, which tells a user already
    // running this CLI to install it (issue #130). Its full CLI-native
    // remediation (now long enough to carry a `--config-dir`, issue #149) is
    // printed once under "Next steps" below rather than duplicated inline
    // (issue #152); the inline pointer keeps the failing check actionable
    // without going bare. All other checks render their own inline `reason`.
    for (const check of primaryChecks) {
      const icon = check.status === 'ok' ? '✓' : '✗'
      const version = check.version !== undefined ? ` (${check.version})` : ''
      const reasonText =
        check.error !== undefined ? 'invalid; see the fix under Next steps' : check.reason
      const reason = reasonText !== undefined ? ` — ${reasonText}` : ''
      process.stdout.write(`  ${icon} ${check.name}${version}${reason}\n`)
    }

    if (result.warnings.length > 0) {
      process.stdout.write('\nWarnings:\n')
      for (const warning of result.warnings) {
        process.stdout.write(`  ⚠ ${warning}\n`)
      }
    }

    if (result.ready) {
      process.stdout.write('\nSystem ready.\n')
      return 0
    }

    // The library's `nextSteps` carries the config check's `reason` prose
    // (with its "install @vaultkeeper/cli" remediation) for an invalid
    // config. Swap that one entry for the CLI-native remediation built from
    // the check's structured `error`, leaving every other next step intact
    // (issue #130).
    const invalidConfig = result.checks.find(
      (check) => check.name === 'config' && check.error !== undefined,
    )
    const nextSteps =
      invalidConfig?.error !== undefined
        ? [
            formatPreflightConfigError(invalidConfig.error, configDir),
            ...result.nextSteps.filter(
              (step) => step !== (invalidConfig.reason ?? 'Config file is invalid.'),
            ),
          ]
        : result.nextSteps

    process.stdout.write('\nNext steps:\n')
    for (const step of nextSteps) {
      process.stdout.write(`  → ${step}\n`)
    }
    return 1
  } catch (err) {
    process.stderr.write(`${formatError(err, configDir)}\n`)
    return 1
  }
}
