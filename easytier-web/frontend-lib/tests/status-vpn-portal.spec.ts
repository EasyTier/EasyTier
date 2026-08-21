import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import Status from '../src/components/Status.vue'
import { VpnPortalClientState, type NetworkInstance } from '../src/types/network'

vi.mock('vue-i18n', () => ({
  useI18n: () => ({ t: (key: string) => key }),
}))

vi.mock('@vueuse/core', () => ({
  useTimeAgo: () => '',
}))

vi.mock('../src/components/NetworkChart.vue', () => ({
  default: defineComponent({ render: () => h('div') }),
}))

vi.mock('primevue', () => {
  const PassThrough = defineComponent({
    setup(_, { slots }) {
      return () => h('div', slots.default?.())
    },
  })
  const CardStub = defineComponent({
    setup(_, { slots }) {
      return () => h('div', [slots.title?.(), slots.content?.()])
    },
  })
  const ButtonStub = defineComponent({
    props: { label: String },
    emits: ['click'],
    setup(props, { emit }) {
      return () => h('button', {
        'data-label': props.label,
        onClick: (event: MouseEvent) => emit('click', event),
      }, props.label)
    },
  })

  return {
    Badge: PassThrough,
    Button: ButtonStub,
    Card: CardStub,
    Chip: PassThrough,
    Column: PassThrough,
    DataTable: PassThrough,
    Dialog: PassThrough,
    Divider: PassThrough,
    ScrollPanel: PassThrough,
    Tag: PassThrough,
    Timeline: PassThrough,
  }
})

function runningInstance(): NetworkInstance {
  return {
    instance_id: '12345678-9abc-def0-fedc-ba9876543210',
    running: true,
    error_msg: '',
    detail: {
      dev_name: 'tun0',
      running: true,
      events: [],
      routes: [],
      peers: [],
      peer_route_pairs: [],
      my_node_info: {
        virtual_ipv4: { address: { addr: 0x0a000001 }, network_length: 24 },
        hostname: 'portal-node',
        version: 'test',
        ips: {
          public_ipv4: { addr: 0 },
          interface_ipv4s: [],
          public_ipv6: { part1: 0, part2: 0, part3: 0, part4: 0 },
          interface_ipv6s: [],
          listeners: [],
        },
        stun_info: { udp_nat_type: 0, tcp_nat_type: 0, last_update_time: 0 },
        listeners: [],
        peer_id: 1,
      },
    },
  }
}

describe('Status VPN Portal details', () => {
  it('fetches client configs only when the user opens the dialog', async () => {
    const getVpnPortalInfo = vi.fn(async () => ({
      vpn_type: 'wireguard',
      client_config: '',
      connected_clients: [],
      listener: '0.0.0.0:22022',
      clients: [{
        name: 'phone-a',
        virtual_ip: '10.0.0.10',
        groups: ['ops'],
        state: VpnPortalClientState.ONLINE,
        peer_id: 42,
        endpoint: '203.0.113.5:51820',
        tunnel_ip: '192.0.2.1',
        client_config: '[Interface]\nPrivateKey = secret',
      }],
    }))
    const wrapper = mount(Status, {
      props: {
        curNetworkInst: runningInstance(),
        api: { get_vpn_portal_info: getVpnPortalInfo } as any,
      },
      global: {
        directives: { tooltip: () => {} },
        stubs: { HumanEvent: true },
      },
    })

    try {
      expect(getVpnPortalInfo).not.toHaveBeenCalled()

      await wrapper.find('button[data-label="show_vpn_portal_config"]').trigger('click')
      await flushPromises()

      expect(getVpnPortalInfo).toHaveBeenCalledOnce()
      expect(getVpnPortalInfo).toHaveBeenCalledWith('12345678-9abc-def0-fedc-ba9876543210')
      expect(wrapper.text()).toContain('phone-a · 10.0.0.10')
      expect(wrapper.text()).toContain('203.0.113.5:51820')
      expect(wrapper.text()).toContain('PrivateKey = secret')
    } finally {
      wrapper.unmount()
    }
  })

  it('renders the unconfigured portal sentinel as an empty state', async () => {
    const getVpnPortalInfo = vi.fn(async () => ({
      vpn_type: 'null',
      client_config: '',
      connected_clients: [],
      clients: [],
    }))
    const wrapper = mount(Status, {
      props: {
        curNetworkInst: runningInstance(),
        api: { get_vpn_portal_info: getVpnPortalInfo } as any,
      },
      global: {
        directives: { tooltip: () => {} },
        stubs: { HumanEvent: true },
      },
    })

    try {
      await wrapper.find('button[data-label="show_vpn_portal_config"]').trigger('click')
      await flushPromises()

      expect(wrapper.text()).toContain('vpn_portal_not_configured')
      expect(wrapper.text()).not.toContain('vpn_portal_type: null')
    } finally {
      wrapper.unmount()
    }
  })
})
