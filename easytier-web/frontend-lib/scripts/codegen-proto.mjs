import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { delimiter, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const protoRoot = resolve(root, '../../easytier/src/proto')
const generatedRoot = resolve(root, 'src/generated')
const outDir = resolve(generatedRoot, 'proto')
const nodeBinDir = resolve(root, 'node_modules/.bin')

const protocWrapper = require.resolve('@protobuf-ts/protoc/protoc.js')
const protobufTsPluginRoot = dirname(require.resolve('@protobuf-ts/plugin/package.json'))

const protoFiles = [
  'common.proto',
  'acl.proto',
  'api_instance.proto',
  'api_manage.proto',
  'peer_rpc.proto',
  'error.proto',
]

function installGeneratedFiles(fromDir, toDir) {
  mkdirSync(toDir, { recursive: true })

  for (const entry of readdirSync(fromDir)) {
    const source = resolve(fromDir, entry)
    const target = resolve(toDir, entry)

    if (statSync(source).isDirectory()) {
      installGeneratedFiles(source, target)
      continue
    }

    renameSync(source, target)
  }
}

function findExecutableInPath(command, extensions = ['']) {
  const envPath = process.env[pathEnvKey()]
  if (typeof envPath !== 'string') return undefined

  const nodeBinSuffix = ['node_modules/.bin', 'node_modules\\.bin']
  for (const entry of envPath.split(delimiter)) {
    if (!entry || nodeBinSuffix.some((suffix) => entry.endsWith(suffix))) continue

    for (const extension of extensions) {
      const candidate = resolve(entry, `${command}${extension}`)
      if (existsSync(candidate)) return candidate
    }
  }

  return undefined
}

function pathEnvKey() {
  return Object.keys(process.env).find((key) => key.toLowerCase() === 'path') ?? 'PATH'
}

function withNodeBinPath() {
  const key = pathEnvKey()
  const currentPath = process.env[key]

  return {
    ...process.env,
    [key]: currentPath ? `${nodeBinDir}${delimiter}${currentPath}` : nodeBinDir,
  }
}

function getProtocCommand() {
  const extensions = process.platform === 'win32' ? ['.exe'] : ['']
  const systemProtoc = findExecutableInPath('protoc', extensions)

  if (systemProtoc) {
    return {
      command: systemProtoc,
      argsPrefix: ['--proto_path', protobufTsPluginRoot],
    }
  }

  return {
    command: process.execPath,
    argsPrefix: [protocWrapper],
  }
}

mkdirSync(generatedRoot, { recursive: true })
const tmpDir = mkdtempSync(resolve(generatedRoot, '.proto-'))
const protocCommand = getProtocCommand()

try {
  const result = spawnSync(protocCommand.command, [
    ...protocCommand.argsPrefix,
    '-I',
    protoRoot,
    `--ts_out=${tmpDir}`,
    '--ts_opt=use_proto_field_name,server_none,client_none,ts_nocheck',
    ...protoFiles.map((file) => resolve(protoRoot, file)),
  ], {
    cwd: root,
    env: withNodeBinPath(),
    stdio: 'inherit',
    shell: false,
  })

  if (result.error) {
    throw result.error
  }

  const status = result.status ?? 1
  if (status === 0) {
    installGeneratedFiles(tmpDir, outDir)
  }

  process.exit(status)
} finally {
  rmSync(tmpDir, { recursive: true, force: true })
}
