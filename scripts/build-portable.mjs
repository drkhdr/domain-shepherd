import { existsSync, rmSync, renameSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { withGitMetaEnv } from './git-meta.mjs'

const root = process.cwd()
let exitCode = 0
const apiRoutePath = join(root, 'src', 'app', 'api', 'probe', 'route.ts')
const portableRoutePath = join(dirname(apiRoutePath), 'route.ts.portable')

try {
  const routeWasPresent = existsSync(apiRoutePath)
  if (routeWasPresent) {
    renameSync(apiRoutePath, portableRoutePath)
  }

  rmSync(join(root, '.next'), { recursive: true, force: true })

  const env = {
    ...withGitMetaEnv(process.env, root),
    PORTABLE_BUILD: '1',
  }

  const result = spawnSync('npx next build', {
    cwd: root,
    env,
    stdio: 'inherit',
    shell: true,
  })

  if (result.error) {
    throw result.error
  }

  if (result.status !== 0) {
    exitCode = result.status ?? 1
  }
} catch (error) {
  console.error(error)
  exitCode = 1
} finally {
  if (existsSync(portableRoutePath) && !existsSync(apiRoutePath)) {
    renameSync(portableRoutePath, apiRoutePath)
  }
}

if (exitCode !== 0) {
  process.exit(exitCode)
}
