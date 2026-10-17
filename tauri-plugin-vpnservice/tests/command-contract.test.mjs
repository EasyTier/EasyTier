import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

test('every direct Rust mobile command matches an annotated Kotlin method exactly', () => {
  const rust = readFileSync(new URL('../src/mobile.rs', import.meta.url), 'utf8')
  const kotlin = readFileSync(new URL('../android/src/main/java/VpnServicePlugin.kt', import.meta.url), 'utf8')
  const methods = new Set([...kotlin.matchAll(/@Command\s+(?:@[^\n]+\s+)*fun (\w+)\(/g)].map(match => match[1]))
  const calls = [...rust.matchAll(/\.run_mobile_plugin\("([^"]+)"/g)].map(match => match[1])
  assert.ok(calls.length >= 8, 'must cover storage and VPN commands')
  for (const command of calls) assert.ok(methods.has(command), `unregistered Kotlin command: ${command}`)
})
