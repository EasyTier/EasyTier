import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import PrimeVue from 'primevue/config'
import { afterEach, describe, expect, it, vi } from 'vitest'
import Status from '../src/components/Status.vue'
import type { NetworkInstance } from '../src/types/network'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

const wrappers: VueWrapper[] = []

afterEach(() => {
  wrappers.splice(0).forEach(wrapper => wrapper.unmount())
})

async function render(localStun: unknown, peerStun: unknown, lossRate?: number) {
  const instance = {
    instance_id: '12345678-9abc-def0-fedc-ba9876543210',
    running: true,
    detail: {
      my_node_info: {
        hostname: 'local-node',
        version: 'test',
        peer_id: 1,
        stun_info: localStun,
      },
      peer_route_pairs: [{
        route: {
          hostname: 'remote-node',
          version: 'test',
          cost: 1,
          stun_info: peerStun,
        },
        peer: {
          conns: [{
            conn_id: 'connection',
            ...(lossRate === undefined ? {} : { loss_rate: lossRate }),
          }],
        },
      }],
    },
  } as unknown as NetworkInstance
  const wrapper = mount(Status, {
    props: {
      curNetworkInst: instance,
      api: { get_network_config: vi.fn(async () => ({})) } as any,
    },
    global: {
      plugins: [PrimeVue],
      directives: { tooltip: () => {} },
      stubs: { HumanEvent: true, NetworkChart: true, VpnPortalDialog: true },
    },
  })
  wrappers.push(wrapper)
  await flushPromises()
  return wrapper
}

describe('status protobuf JSON rendering', () => {
  it('renders enum names and omitted zero loss in the real peer table', async () => {
    const wrapper = await render({ udp_nat_type: 'FullCone' }, { udp_nat_type: 'PortRestricted' })
    const rows = wrapper.findAll('tbody tr')
    expect(rows[0].text()).toContain('Full Cone')
    expect(rows[0].text()).not.toContain('0%')
    expect(rows[1].text()).toContain('Port Restricted')
    expect(rows[1].text()).toContain('0%')
    await wrapper.findAll('button').find(button => button.text() === 'show_node_details')!.trigger('click')
    expect(wrapper.text()).toContain('UDP NAT Type: Full Cone')
    expect(wrapper.text()).not.toContain('UDP NAT Type: undefined')
  })

  it('renders omitted enum defaults as Unknown but leaves missing STUN data blank', async () => {
    const wrapper = await render({}, undefined, 0.25)
    const rows = wrapper.findAll('tbody tr')
    expect(rows[0].text()).toContain('Unknown')
    expect(rows[1].text()).not.toContain('Unknown')
    expect(rows[1].text()).toContain('25%')
    expect(wrapper.text()).toContain('UDP NAT Type: Unknown')
  })

  it('preserves numeric NAT values from older backends', async () => {
    const wrapper = await render({ udp_nat_type: 1 }, { udp_nat_type: 6 }, 0.5)
    const rows = wrapper.findAll('tbody tr')
    expect(rows[0].text()).toContain('Open Internet')
    expect(rows[1].text()).toContain('Symmetric')
    expect(rows[1].text()).toContain('50%')
  })
})
