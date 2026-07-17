import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import ts from 'typescript'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '..')
const generatedApiManagePath = path.join(projectRoot, 'src/generated/proto/api_manage.ts')
const distPath = path.join(projectRoot, 'dist/easytier-frontend-lib.js')

const { NetworkTypes } = await import(pathToFileURL(distPath))

const {
  AclAction,
  AclChainType,
  AclProtocol,
  CompressionAlgoPb,
  DEFAULT_NETWORK_CONFIG,
  NetworkingMethod,
  normalizeNetworkConfig,
  toBackendNetworkConfig,
} = NetworkTypes

const BOOLEAN_CONFIG_FIELDS = [
  'dhcp',
  'enable_vpn_portal',
  'advanced_settings',
  'latency_first',
  'use_smoltcp',
  'disable_ipv6',
  'enable_kcp_proxy',
  'disable_kcp_input',
  'disable_p2p',
  'bind_device',
  'no_tun',
  'enable_exit_node',
  'relay_all_peer_rpc',
  'multi_thread',
  'enable_relay_network_whitelist',
  'enable_manual_routes',
  'proxy_forward_by_system',
  'disable_encryption',
  'enable_socks5',
  'disable_udp_hole_punching',
  'enable_magic_dns',
  'enable_private_mode',
  'enable_quic_proxy',
  'disable_quic_input',
  'disable_sym_hole_punching',
  'p2p_only',
  'lazy_p2p',
  'need_p2p',
  'disable_upnp',
  'ipv6_public_addr_provider',
  'ipv6_public_addr_auto',
  'disable_relay_data',
  'enable_udp_broadcast_relay',
  'disable_tcp_hole_punching',
]

function readGeneratedNetworkConfigFields() {
  const source = ts.createSourceFile(
    generatedApiManagePath,
    fs.readFileSync(generatedApiManagePath, 'utf8'),
    ts.ScriptTarget.Latest,
    true,
  )

  for (const statement of source.statements) {
    if (!ts.isInterfaceDeclaration(statement) || statement.name.text !== 'NetworkConfig') {
      continue
    }

    return statement.members
      .filter(ts.isPropertySignature)
      .map((member) => member.name.getText(source).replace(/^['"]|['"]$/g, ''))
  }

  throw new Error(`NetworkConfig interface not found in ${generatedApiManagePath}`)
}

function expectNoCamelCaseKeys(value, pathSegments = []) {
  if (!value || typeof value !== 'object') {
    return
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => expectNoCamelCaseKeys(item, [...pathSegments, String(index)]))
    return
  }

  for (const [key, child] of Object.entries(value)) {
    assert.equal(
      /[A-Z]/.test(key),
      false,
      `JSON key should use proto field name: ${[...pathSegments, key].join('.')}`,
    )
    expectNoCamelCaseKeys(child, [...pathSegments, key])
  }
}

function allFieldFixture() {
  return {
    ...DEFAULT_NETWORK_CONFIG(),
    instance_id: '11111111-2222-3333-4444-555555555555',
    dhcp: false,
    virtual_ipv4: '10.9.8.7',
    network_length: 25,
    hostname: 'frontend-e2e',
    network_name: 'full-field-network',
    network_secret: 'full-field-secret',
    networking_method: NetworkingMethod.Manual,
    public_server_url: 'tcp://public.example:11010',
    peer_urls: [' tcp://peer-a:11010 ', '', 'udp://peer-b:11010'],
    peers: [
      {
        uri: 'tcp://peer-a:11010',
        peer_public_key: 'peer-a-public-key',
      },
    ],
    proxy_cidrs: ['10.10.0.0/16', '192.168.2.0/24->10.99.0.0/24'],
    enable_vpn_portal: true,
    vpn_portal_listen_port: 23000,
    vpn_portal_client_network_addr: '10.88.0.0',
    vpn_portal_client_network_len: 24,
    advanced_settings: true,
    listener_urls: ['tcp://0.0.0.0:12010', 'udp://0.0.0.0:12010'],
    latency_first: true,
    dev_name: 'et-full',
    use_smoltcp: true,
    disable_ipv6: true,
    enable_kcp_proxy: true,
    disable_kcp_input: true,
    disable_p2p: true,
    bind_device: false,
    no_tun: true,
    enable_exit_node: true,
    relay_all_peer_rpc: true,
    multi_thread: false,
    enable_relay_network_whitelist: true,
    relay_network_whitelist: ['10.0.0.0/8', 'fd00::/8'],
    enable_manual_routes: true,
    routes: ['10.20.0.0/16', 'fd00:20::/64'],
    exit_nodes: ['10.9.8.1', 'fd00::1'],
    proxy_forward_by_system: true,
    disable_encryption: true,
    enable_socks5: true,
    socks5_port: 1081,
    disable_udp_hole_punching: true,
    mtu: 1280,
    mapped_listeners: ['tcp://127.0.0.1:13010'],
    enable_magic_dns: true,
    enable_private_mode: true,
    enable_quic_proxy: true,
    disable_quic_input: true,
    quic_listen_port: 14010,
    port_forwards: [
      {
        proto: 'tcp',
        bind_ip: '127.0.0.1',
        bind_port: 8080,
        dst_ip: '10.9.8.7',
        dst_port: 80,
      },
      {
        proto: 'udp',
        bind_ip: '0.0.0.0',
        bind_port: 5353,
        dst_ip: '10.9.8.8',
        dst_port: 53,
      },
    ],
    disable_sym_hole_punching: true,
    p2p_only: true,
    data_compress_algo: CompressionAlgoPb.Zstd,
    encryption_algorithm: 'aes-gcm',
    disable_tcp_hole_punching: true,
    secure_mode: {
      enabled: true,
      local_private_key: 'private-key',
      local_public_key: 'public-key',
    },
    acl: {
      acl_v1: {
        group: {
          declares: [
            {
              group_name: 'ops',
              group_secret: 'ops-secret',
            },
          ],
          members: ['node-a', 'node-b'],
        },
        chains: [
          {
            name: 'forward-chain',
            chain_type: AclChainType.Forward,
            description: 'forward traffic',
            enabled: true,
            default_action: AclAction.Drop,
            rules: [
              {
                name: 'allow-web',
                description: 'allow web traffic',
                priority: 100,
                enabled: true,
                protocol: AclProtocol.TCP,
                ports: ['80', '443'],
                source_ips: ['10.0.0.0/8'],
                destination_ips: ['10.9.8.7/32'],
                source_ports: ['1024-65535'],
                action: AclAction.Allow,
                rate_limit: 1000,
                burst_limit: 2000,
                stateful: true,
                source_groups: ['ops'],
                destination_groups: ['web'],
              },
            ],
          },
        ],
      },
    },
    credential_file: '/tmp/easytier-credential.toml',
    lazy_p2p: true,
    need_p2p: true,
    instance_recv_bps_limit: '9007199254740993',
    disable_upnp: true,
    ipv6_public_addr_provider: true,
    ipv6_public_addr_auto: true,
    ipv6_public_addr_prefix: '2001:db8:1::/64',
    disable_relay_data: true,
    enable_udp_broadcast_relay: true,
    socket_mark: 1234,
  }
}

function assertFixtureCoversGeneratedFields() {
  const generatedFields = readGeneratedNetworkConfigFields()
  const fixtureFields = new Set(Object.keys(allFieldFixture()))
  const missing = generatedFields.filter((field) => !fixtureFields.has(field))

  assert.deepEqual(missing, [], 'all generated NetworkConfig fields should be represented in the fixture')
}

function assertFullFieldRoundTrip() {
  const input = allFieldFixture()
  const normalized = normalizeNetworkConfig(input)

  assert.equal(normalized.peer_urls.join(','), 'tcp://peer-a:11010,udp://peer-b:11010')
  assert.equal(normalized.instance_recv_bps_limit, '9007199254740993')
  assert.equal(normalized.data_compress_algo, CompressionAlgoPb.Zstd)
  assert.equal(normalized.acl.acl_v1.chains[0].chain_type, AclChainType.Forward)
  assert.equal(normalized.acl.acl_v1.chains[0].rules[0].protocol, AclProtocol.TCP)

  const backend = toBackendNetworkConfig(normalized)
  expectNoCamelCaseKeys(backend)

  for (const field of readGeneratedNetworkConfigFields()) {
    assert.ok(field in backend, `backend JSON should include fixture field ${field}`)
  }

  assert.equal(backend.networking_method, 'Manual')
  assert.equal(backend.public_server_url, '')
  assert.deepEqual(backend.peer_urls, ['tcp://peer-a:11010', 'udp://peer-b:11010'])
  assert.equal(backend.peers[0].peer_public_key, 'peer-a-public-key')
  assert.deepEqual(backend.peers[1], { uri: 'udp://peer-b:11010' })
  assert.equal(backend.data_compress_algo, 'Zstd')
  assert.equal(backend.instance_recv_bps_limit, '9007199254740993')
  assert.equal(backend.secure_mode.enabled, true)
  assert.equal(backend.secure_mode.local_private_key, 'private-key')
  assert.equal(backend.acl.acl_v1.chains[0].chain_type, 'Forward')
  assert.equal(backend.acl.acl_v1.chains[0].default_action, 'Drop')
  assert.equal(backend.acl.acl_v1.chains[0].rules[0].protocol, 'TCP')
  assert.equal(backend.acl.acl_v1.chains[0].rules[0].action, 'Allow')
  assert.equal(backend.port_forwards[1].proto, 'udp')
  assert.equal(backend.socket_mark, 1234)
}

function assertBooleanFieldValuesPreserved() {
  const input = allFieldFixture()
  const normalized = normalizeNetworkConfig(input)
  const backend = toBackendNetworkConfig(normalized)

  for (const field of BOOLEAN_CONFIG_FIELDS) {
    assert.equal(
      normalized[field],
      input[field],
      `normalized config should preserve boolean field ${field}`,
    )
    assert.equal(
      backend[field],
      input[field],
      `backend JSON should preserve boolean field ${field}`,
    )
  }
}

function assertEnumCompatibility() {
  const normalized = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    networking_method: 'Manual',
    data_compress_algo: 'Zstd',
    acl: {
      acl_v1: {
        group: { declares: [], members: [] },
        chains: [
          {
            chain_type: 'Forward',
            default_action: 'Drop',
            rules: [
              {
                protocol: 'TCP',
                action: 'Allow',
              },
            ],
          },
        ],
      },
    },
  })

  assert.equal(normalized.data_compress_algo, CompressionAlgoPb.Zstd)
  assert.equal(normalized.acl.acl_v1.chains[0].chain_type, AclChainType.Forward)
  assert.equal(normalized.acl.acl_v1.chains[0].default_action, AclAction.Drop)
  assert.equal(normalized.acl.acl_v1.chains[0].rules[0].protocol, AclProtocol.TCP)
  assert.equal(normalized.acl.acl_v1.chains[0].rules[0].action, AclAction.Allow)

  const backend = toBackendNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    data_compress_algo: 'Zstd',
    acl: {
      acl_v1: {
        group: { declares: [], members: [] },
        chains: [
          {
            chain_type: 'Forward',
            default_action: 'Drop',
            rules: [
              {
                protocol: 'TCP',
                action: 'Allow',
              },
            ],
          },
        ],
      },
    },
  })

  assert.equal(backend.data_compress_algo, 'Zstd')
  assert.equal(backend.acl.acl_v1.chains[0].chain_type, 'Forward')
  assert.equal(backend.acl.acl_v1.chains[0].rules[0].protocol, 'TCP')
}

function assertAclDefaultsAndExplicitZero() {
  const partialAcl = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    acl: {
      acl_v1: {
        group: { declares: [], members: [] },
        chains: [{ rules: [{}] }],
      },
    },
  })
  const defaultedChain = partialAcl.acl.acl_v1.chains[0]

  assert.equal(defaultedChain.chain_type, AclChainType.UnspecifiedChain)
  assert.equal(defaultedChain.default_action, AclAction.Allow)
  assert.equal(defaultedChain.rules[0].protocol, AclProtocol.Any)
  assert.equal(defaultedChain.rules[0].action, AclAction.Allow)

  const explicitZero = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    acl: {
      acl_v1: {
        group: { declares: [], members: [] },
        chains: [
          {
            chain_type: 0,
            default_action: 0,
            rules: [{ protocol: 0, action: 0 }],
          },
        ],
      },
    },
  })
  const zeroChain = explicitZero.acl.acl_v1.chains[0]

  assert.equal(zeroChain.chain_type, AclChainType.UnspecifiedChain)
  assert.equal(zeroChain.default_action, AclAction.Noop)
  assert.equal(zeroChain.rules[0].protocol, AclProtocol.Unspecified)
  assert.equal(zeroChain.rules[0].action, AclAction.Noop)
}

function assertNetworkingMethodNormalization() {
  const publicServer = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    networking_method: 'PublicServer',
    public_server_url: ' tcp://public.example:11010 ',
    peer_urls: ['tcp://manual.example:11010'],
  })

  assert.equal(publicServer.networking_method, NetworkingMethod.Manual)
  assert.equal(publicServer.public_server_url, '')
  assert.deepEqual(publicServer.peer_urls, ['tcp://public.example:11010'])

  const standalone = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    networking_method: 'Standalone',
    peer_urls: ['tcp://manual.example:11010'],
  })

  assert.equal(standalone.networking_method, NetworkingMethod.Manual)
  assert.deepEqual(standalone.peer_urls, [])

  const missing = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    networking_method: undefined,
    peer_urls: [' tcp://one ', '', 'udp://two '],
  })

  assert.deepEqual(missing.peer_urls, ['tcp://one', 'udp://two'])

  const publicServerMissingUrl = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    networking_method: 'PublicServer',
    public_server_url: '',
    peer_urls: ['tcp://manual.example:11010'],
  })

  assert.deepEqual(publicServerMissingUrl.peer_urls, [])
}

function assertPeerPublicKeysPreserved() {
  const normalized = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    peer_urls: [],
    peers: [
      {
        uri: ' tcp://peer-a:11010 ',
        peer_public_key: 'peer-a-public-key',
      },
    ],
  })

  assert.deepEqual(normalized.peer_urls, ['tcp://peer-a:11010'])
  assert.deepEqual(normalized.peers, [
    {
      uri: 'tcp://peer-a:11010',
      peer_public_key: 'peer-a-public-key',
    },
  ])

  const unchangedUrl = toBackendNetworkConfig({
    ...normalized,
    peer_urls: ['tcp://peer-a:11010', 'tcp://peer-b:11010'],
  })

  assert.equal(unchangedUrl.peers[0].peer_public_key, 'peer-a-public-key')
  assert.deepEqual(unchangedUrl.peers[1], { uri: 'tcp://peer-b:11010' })

  const changedUrl = toBackendNetworkConfig({
    ...normalized,
    peer_urls: ['tcp://peer-c:11010'],
  })

  assert.deepEqual(changedUrl.peers, [{ uri: 'tcp://peer-c:11010' }])

  const clearedUrls = toBackendNetworkConfig({
    ...normalized,
    peer_urls: [],
  })

  assert.deepEqual(clearedUrls.peer_urls ?? [], [])
  assert.deepEqual(clearedUrls.peers ?? [], [])
}

function assertNumberBoundaries() {
  const safeLimit = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: '12345',
  })
  assert.equal(safeLimit.instance_recv_bps_limit, 12345)

  const largeLimit = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: '9007199254740993',
  })
  assert.equal(largeLimit.instance_recv_bps_limit, '9007199254740993')
  assert.equal(toBackendNetworkConfig(largeLimit).instance_recv_bps_limit, '9007199254740993')

  const invalidNumbers = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    mtu: Number.NaN,
    instance_recv_bps_limit: Number.POSITIVE_INFINITY,
  })
  assert.equal(invalidNumbers.mtu, null)
  assert.equal(invalidNumbers.instance_recv_bps_limit, null)

  const emptyLimit = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: '',
  })
  assert.equal(emptyLimit.instance_recv_bps_limit, null)

  const zeroLimit = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: '0',
  })
  assert.equal(zeroLimit.instance_recv_bps_limit, null)
  assert.equal(toBackendNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: 0,
  }).instance_recv_bps_limit, undefined)

  const oversizedLimit = normalizeNetworkConfig({
    ...DEFAULT_NETWORK_CONFIG(),
    instance_recv_bps_limit: '18446744073709551616',
  })
  assert.equal(oversizedLimit.instance_recv_bps_limit, null)
}

const tests = [
  assertFixtureCoversGeneratedFields,
  assertFullFieldRoundTrip,
  assertBooleanFieldValuesPreserved,
  assertEnumCompatibility,
  assertAclDefaultsAndExplicitZero,
  assertNetworkingMethodNormalization,
  assertPeerPublicKeysPreserved,
  assertNumberBoundaries,
]

for (const test of tests) {
  test()
  console.log(`ok ${test.name}`)
}
