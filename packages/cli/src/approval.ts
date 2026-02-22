import * as readline from 'node:readline'
import type { ApprovalInfo } from './types.js'

/**
 * Display an interactive approval prompt on the TTY.
 *
 * @param info - The access request details to display.
 * @returns `true` if the user approves, `false` otherwise.
 * @throws If stdin is not a TTY.
 *
 * @internal
 */
export async function promptApproval(info: ApprovalInfo): Promise<boolean> {
  if (!process.stdin.isTTY) {
    throw new Error(
      'Secret access requires interactive approval. Run this command in a terminal.',
    )
  }

  const lines = [
    '┌─────────────────────────────────────────────────┐',
    '│  Secret Access Request                          │',
    '│                                                 │',
    `│  Caller:  ${pad(info.caller)}│`,
    `│  Trust:   ${pad(info.trustInfo)}│`,
    `│  Secret:  ${pad(info.secret)}│`,
  ]

  if (info.reason !== undefined) {
    lines.push(`│  Reason:  ${pad(info.reason)}│`)
  }

  lines.push(
    '│                                                 │',
    '│  Allow? [y/N]                                   │',
    '└─────────────────────────────────────────────────┘',
  )

  process.stderr.write(lines.join('\n') + '\n')

  const answer = await readLine()
  return answer.trim().toLowerCase() === 'y'
}

function pad(text: string): string {
  const maxWidth = 37 // 49 total width - 10 prefix "│  Label:  " - 1 trailing "│"
  if (text.length >= maxWidth) {
    return text.slice(0, maxWidth - 3) + '...'
  }
  return text + ' '.repeat(maxWidth - text.length)
}

function readLine(): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stderr,
    })
    rl.question('', (answer) => {
      rl.close()
      resolve(answer)
    })
  })
}
