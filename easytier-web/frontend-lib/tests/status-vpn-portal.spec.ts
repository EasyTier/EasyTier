import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import Status from '../src/components/Status.vue'
import VpnPortalDialog from '../src/components/VpnPortalDialog.vue'
import { DEFAULT_NETWORK_CONFIG, VpnPortalClientState, type NetworkInstance } from '../src/types/network'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('@vueuse/core', () => ({ useTimeAgo: () => '' }))
vi.mock('../src/components/NetworkChart.vue', () => ({ default: defineComponent({ render: () => h('div') }) }))

vi.mock('primevue', () => {
  const PassThrough = defineComponent({ setup: (_, { slots }) => () => h('div', slots.default?.()) })
  const Input = defineComponent({
    props: ['modelValue', 'inputId'],
    emits: ['update:modelValue'],
    setup: (props, { attrs, emit }) => () => h('input', {
      ...attrs,
      id: props.inputId ?? attrs.id,
      value: props.modelValue ?? '',
      onInput: (event: Event) => emit('update:modelValue', (event.target as HTMLInputElement).value),
    }),
  })
  const Button = defineComponent({
    props: { label: String, disabled: Boolean, type: { type: String, default: 'button' } },
    emits: ['click'],
    setup: (props, { emit }) => () => h('button', {
      'data-label': props.label,
      disabled: props.disabled,
      type: props.type,
      onClick: (event: MouseEvent) => emit('click', event),
    }, props.label),
  })
  const Card = defineComponent({ setup: (_, { slots }) => () => h('div', [slots.title?.(), slots.content?.()]) })
  return {
    Badge: PassThrough, Button, Card, Chip: PassThrough, Column: PassThrough,
    DataTable: PassThrough, Dialog: PassThrough, Divider: PassThrough,
    InputText: Input, InputNumber: Input, MultiSelect: Input, Tag: PassThrough, Timeline: PassThrough,
  }
})

function runningInstance(): NetworkInstance {
  return {
    instance_id: '12345678-9abc-def0-fedc-ba9876543210', running: true, error_msg: '',
    detail: {
      dev_name: 'tun0', running: true, events: [], routes: [], peers: [],
      peer_route_pairs: [{ route: { ipv4_addr: '10.0.0.2/24' } } as any],
      my_node_info: {
        virtual_ipv4: { address: { addr: 0x0a000001 }, network_length: 24 },
        hostname: 'portal-node', version: 'test',
        ips: {
          public_ipv4: { addr: 0xcb007109 }, interface_ipv4s: [],
          public_ipv6: { part1: 0, part2: 0, part3: 0, part4: 0 }, interface_ipv6s: [], listeners: [],
        },
        stun_info: { udp_nat_type: 0, tcp_nat_type: 0, last_update_time: 0 }, listeners: [], peer_id: 1,
      },
    },
  }
}

function backend() {
  const config = DEFAULT_NETWORK_CONFIG()
  config.vpn_portal_config = {
    wireguard_listen: '0.0.0.0:22022', wireguard_private_key: 'stable-key',
    clients: [{ name: 'phone-a', virtual_ip: '10.0.0.3/24', groups: [] }],
  }
  const api = {
    get_network_config: vi.fn(async () => structuredClone(config)),
    get_vpn_portal_info: vi.fn(async () => ({
      vpn_type: 'wireguard', listener: 'wg://0.0.0.0:22022',
      clients: config.vpn_portal_config!.clients.map(client => ({
        name: client.name, virtual_ip: client.virtual_ip.split('/')[0], groups: client.groups,
        state: VpnPortalClientState.OFFLINE,
        client_config: `[Interface]\nPrivateKey = device-secret\nAddress = ${client.virtual_ip.split('/')[0]}/32\n\n[Peer]\nPublicKey = server-key\nAllowedIPs = 10.0.0.0/24\nEndpoint = 0.0.0.0:22022 # replace wildcard with the public address\nPersistentKeepalive = 25\n`,
      })),
    })),
    add_vpn_portal_client: vi.fn(async (_: string, client: any) => {
      config.vpn_portal_config!.clients.push({ ...client, groups: [...client.groups] })
    }),
    remove_vpn_portal_client: vi.fn(async (_: string, name: string) => {
      config.vpn_portal_config!.clients = config.vpn_portal_config!.clients.filter(client => client.name !== name)
    }),
  }
  return { api, config }
}

const wrappers: VueWrapper[] = []
function render(component: any, api: any, extra: Record<string, any> = {}) {
  const instance = runningInstance()
  const wrapper = mount(component, {
    props: component === Status ? { curNetworkInst: instance, api, ...extra } : { instance, api, ...extra },
    global: { directives: { tooltip: () => {} }, stubs: { HumanEvent: true } },
  })
  wrappers.push(wrapper)
  return wrapper
}
const button = (wrapper: VueWrapper, label: string) => wrapper.find(`button[data-label="${label}"]`)
async function load() {
  await vi.advanceTimersByTimeAsync(1)
  await flushPromises()
}

beforeEach(() => vi.useFakeTimers())
afterEach(() => {
  wrappers.splice(0).forEach(wrapper => wrapper.unmount())
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('WireGuard devices', () => {
  it('opens device configuration only from an enabled running node', async () => {
    const { api } = backend()
    const wrapper = render(Status, api)
    await flushPromises()
    expect(api.get_vpn_portal_info).not.toHaveBeenCalled()
    await button(wrapper, 'vpn_portal_devices').trigger('click')
    await load()
    expect(api.get_vpn_portal_info).toHaveBeenCalledWith(runningInstance().instance_id)
    expect(wrapper.text()).toContain('phone-a')
    await wrapper.setProps({ curNetworkInst: { ...runningInstance(), running: false } })
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(false)
    expect(wrapper.findComponent(VpnPortalDialog).exists()).toBe(false)
  })

  it.each([undefined, { enabled: false, wireguard_listen: '0.0.0.0:22022', clients: [] }])('hides the entry when the portal is disabled', async portal => {
    const { api, config } = backend()
    config.vpn_portal_config = portal
    const wrapper = render(Status, api)
    await flushPromises()
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(false)
  })

  it('refreshes same-instance settings, retries failures, and stops after unmount', async () => {
    const { api, config } = backend()
    const portal = config.vpn_portal_config
    config.vpn_portal_config = undefined
    api.get_network_config.mockRejectedValueOnce(new Error('temporarily offline'))
    const wrapper = render(Status, api)
    await flushPromises()
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(false)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(api.get_network_config).toHaveBeenCalledTimes(2)
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(false)
    config.vpn_portal_config = portal
    await vi.advanceTimersByTimeAsync(10_000)
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(true)
    config.vpn_portal_config!.enabled = false
    await vi.advanceTimersByTimeAsync(10_000)
    expect(button(wrapper, 'vpn_portal_devices').exists()).toBe(false)
    wrapper.unmount()
    await vi.advanceTimersByTimeAsync(30_000)
    expect(api.get_network_config).toHaveBeenCalledTimes(4)
  })

  it('adds a device with a suggested address and immediately exports the public endpoint', async () => {
    const { api, config } = backend()
    const wrapper = render(VpnPortalDialog, api)
    await load()
    await button(wrapper, 'vpn_portal_add_client').trigger('click')
    expect(wrapper.find<HTMLInputElement>('#vpn_portal_client_address').element.value).toBe('10.0.0.4')
    expect(wrapper.find('#vpn_portal_client_groups').exists()).toBe(false)
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(api.add_vpn_portal_client).toHaveBeenCalledWith(runningInstance().instance_id, {
      name: expect.stringMatching(/^device-[a-f0-9]{8}$/), virtual_ip: '10.0.0.4/24', groups: [],
    })
    expect(config.vpn_portal_config!.wireguard_private_key).toBe('stable-key')
    expect(wrapper.find('pre').text()).toContain('Endpoint = 203.0.113.9:22022')
    expect(wrapper.find('pre').text()).not.toContain('replace wildcard')
    expect(wrapper.find('img').attributes('src')).toContain('data:image/svg+xml')
    expect(button(wrapper, 'vpn_portal_download_config').exists()).toBe(true)
  })

  it('rejects known occupied addresses and duplicate names before submitting', async () => {
    const { api } = backend()
    const wrapper = render(VpnPortalDialog, api)
    await load()
    await button(wrapper, 'vpn_portal_add_client').trigger('click')
    for (const address of ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.0', '10.0.0.255']) {
      await wrapper.find('#vpn_portal_client_address').setValue(address)
      expect(button(wrapper, 'vpn_portal_generate_config').attributes('disabled')).toBeDefined()
      await wrapper.find('form').trigger('submit')
    }
    await wrapper.find('#vpn_portal_client_address').setValue('10.0.0.4')
    await wrapper.find('#vpn_portal_client_name').setValue('phone-a')
    expect(button(wrapper, 'vpn_portal_generate_config').attributes('disabled')).toBeDefined()
    expect(api.add_vpn_portal_client).not.toHaveBeenCalled()
  })

  it('requires a reachable endpoint only when no public address is available', async () => {
    const { api } = backend()
    const instance = runningInstance()
    instance.detail!.my_node_info.ips.public_ipv4.addr = 0
    const wrapper = render(VpnPortalDialog, api, { instance })
    await load()
    await button(wrapper, 'vpn_portal_connect_device').trigger('click')
    expect(wrapper.text()).toContain('vpn_portal_endpoint_required')
    expect(button(wrapper, 'vpn_portal_download_config').exists()).toBe(false)
    await wrapper.find('#vpn_portal_server_endpoint').setValue('vpn.example.com:51820')
    await flushPromises()
    expect(wrapper.find('pre').text()).toContain('Endpoint = vpn.example.com:51820')
    const copy = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: copy }, configurable: true })
    await button(wrapper, 'vpn_portal_copy_client_config').trigger('click')
    expect(copy).toHaveBeenCalledWith(wrapper.find('pre').text() + '\n')
  })

  it('offers connection configs without mutations for read-only networks', async () => {
    const { api } = backend()
    const wrapper = render(VpnPortalDialog, api, { readonly: true })
    await load()
    expect(button(wrapper, 'vpn_portal_add_client').exists()).toBe(false)
    expect(wrapper.find('button[aria-label="vpn_portal_remove_client"]').exists()).toBe(false)
    await button(wrapper, 'vpn_portal_connect_device').trigger('click')
    expect(button(wrapper, 'vpn_portal_download_config').exists()).toBe(true)
  })

  it('keeps failed deletions visible and removes the device only after a successful request', async () => {
    const { api } = backend()
    api.remove_vpn_portal_client.mockRejectedValueOnce(new Error('save failed'))
    const wrapper = render(VpnPortalDialog, api)
    await load()
    await wrapper.find('button[aria-label="vpn_portal_remove_client"]').trigger('click')
    expect(api.remove_vpn_portal_client).not.toHaveBeenCalled()
    await button(wrapper, 'vpn_portal_remove_client').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('phone-a')
    expect(wrapper.find('[role="alert"]').text()).toContain('save failed')
    await button(wrapper, 'vpn_portal_remove_client').trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain('phone-a')
    expect(wrapper.text()).toContain('vpn_portal_no_clients')
  })
})
