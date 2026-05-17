import { spawnSync } from 'node:child_process'

export function resolveGitSha(cwd = process.cwd()) {
  const result = spawnSync('git', ['rev-parse', '--short', 'HEAD'], {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    shell: true,
  })

  if (result.status !== 0) {
    return 'unknown'
  }

  const sha = (result.stdout || '').trim()
  return sha || 'unknown'
}

export function withGitMetaEnv(baseEnv = process.env, cwd = process.cwd()) {
  return {
    ...baseEnv,
    NEXT_PUBLIC_GIT_SHA: resolveGitSha(cwd),
  }
}
