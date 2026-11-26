export const splitUtf8Text = 'vault🔐keeper\n'

export function splitUtf8Script(textExpression = JSON.stringify(splitUtf8Text)): string {
  return `
const output = process.argv.includes('stderr') ? process.stderr : process.stdout
const text = Buffer.from(${textExpression})
const splitInsideLock = Buffer.from('vault').length + 2
output.write(text.subarray(0, splitInsideLock))
setTimeout(() => output.write(text.subarray(splitInsideLock)), 20)
`
}
