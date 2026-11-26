/**
 * Installs packed artifacts using npm's project-scoped consumer behavior.
 */
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/**
 * The parent package manager can export an npmrc `allow-scripts` setting into
 * script environments. npm treats that environment setting like a CLI flag and
 * rejects it for project installs. Drop only that inherited override so npm
 * still reads its normal config files and applies its usual lifecycle policy.
 */
export async function installTarballs(projectDir: string, ...tarballs: string[]): Promise<void> {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !/^npm_config_allow[-_]scripts$/i.test(key)),
  )
  await execFileAsync('npm', ['install', '--no-save', '--no-audit', '--no-fund', ...tarballs], {
    cwd: projectDir,
    env,
  })
}
