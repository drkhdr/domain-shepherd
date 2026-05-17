import { spawnSync } from 'node:child_process'
import { withGitMetaEnv } from './git-meta.mjs'

const root = process.cwd()
const args = process.argv.slice(2)

if (args.length === 0) {
  console.error('Usage: node scripts/run-next-with-git-meta.mjs <next-args...>')
  process.exit(2)
}

const result = spawnSync('npx', ['next', ...args], {
  cwd: root,
  env: withGitMetaEnv(process.env, root),
  stdio: 'inherit',
  shell: true,
})

if (result.error) {
  console.error(result.error)
  process.exit(1)
}

process.exit(result.status ?? 1)
