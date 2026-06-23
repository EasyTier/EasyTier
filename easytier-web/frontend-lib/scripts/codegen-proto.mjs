import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const protoRoot = resolve(root, '../../easytier/src/proto')
const generatedRoot = resolve(root, 'src/generated')
const outDir = resolve(generatedRoot, 'proto')

const protoc = require.resolve('@protobuf-ts/protoc/protoc.js')

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

mkdirSync(generatedRoot, { recursive: true })
const tmpDir = mkdtempSync(resolve(generatedRoot, '.proto-'))

try {
  const result = spawnSync(process.execPath, [
    protoc,
    '-I',
    protoRoot,
    `--ts_out=${tmpDir}`,
    '--ts_opt=use_proto_field_name,server_none,client_none,ts_nocheck',
    ...protoFiles.map((file) => resolve(protoRoot, file)),
  ], {
    cwd: root,
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
