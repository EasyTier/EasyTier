import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import PrimeVue from 'primevue/config'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import Status from '../src/components/Status.vue'
import type { NetworkInstance } from '../src/types/network'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('../src/components/NetworkChart.vue', () => ({
  default: defineComponent({
    name: 'NetworkChart',
    props: ['uploadRate', 'downloadRate'],
    render: () => h('div'),
  }),
}))

const MiB = 1024 * 1024
const GiB = 1024 * MiB

interface Conn { id: string, tx: number, rx: number }

function instance(conns: Conn[], instanceId = '12345678-9abc-def0-fedc-ba9876543210') {
  return {
    instance_id: instanceId,
    running: true,
    detail: {
      my_node_info: { hostname: 'local-node', version: 'test', peer_id: 1 },
      peer_route_pairs: conns.map((conn, idx) => ({
        route: { hostname: `remote-${idx}`, version: 'test', cost: 1 },
        peer: {
          peer_id: idx + 2,
          // protobuf JSON encodes uint64 counters as strings
          conns: [{ conn_id: conn.id, stats: { tx_bytes: String(conn.tx), rx_bytes: String(conn.rx) } }],
        },
      })),
    },
  } as unknown as NetworkInstance
}

const wrappers: VueWrapper[] = []

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
})

afterEach(() => {
  wrappers.splice(0).forEach(wrapper => wrapper.unmount())
  vi.useRealTimers()
})

async function render(inst: NetworkInstance) {
  const wrapper = mount(Status, {
    props: {
      curNetworkInst: inst,
      api: { get_network_config: vi.fn(async () => ({})) } as any,
    },
    global: {
      plugins: [PrimeVue],
      directives: { tooltip: () => {} },
      stubs: { HumanEvent: true, VpnPortalDialog: true },
    },
  })
  wrappers.push(wrapper)
  await flushPromises()
  return wrapper
}

function rates(wrapper: VueWrapper) {
  const chart = wrapper.findComponent({ name: 'NetworkChart' })
  return { up: chart.props('uploadRate'), down: chart.props('downloadRate') }
}

async function tick(wrapper: VueWrapper, inst?: NetworkInstance) {
  if (inst)
    await wrapper.setProps({ curNetworkInst: inst })
  vi.advanceTimersByTime(2000)
  await flushPromises()
  return rates(wrapper)
}

describe('status traffic rate', () => {
  it('does not report lifetime counters as the first rate sample', async () => {
    const wrapper = await render(instance([{ id: 'a', tx: 10 * GiB, rx: 4 * GiB }]))

    expect(await tick(wrapper)).toEqual({ up: '0 B', down: '0 B' })
    expect(await tick(wrapper, instance([{ id: 'a', tx: 10 * GiB + 2 * MiB, rx: 4 * GiB + 4 * MiB }])))
      .toEqual({ up: '1.0 MiB', down: '2.0 MiB' })
  })

  it('ignores counters of peers that disconnect or reconnect', async () => {
    const wrapper = await render(instance([
      { id: 'a', tx: 1 * GiB, rx: 1 * GiB },
      { id: 'b', tx: 8 * GiB, rx: 8 * GiB },
    ]))
    await tick(wrapper)

    // peer b drops off while a keeps sending
    expect(await tick(wrapper, instance([{ id: 'a', tx: 1 * GiB + 2 * MiB, rx: 1 * GiB }])))
      .toEqual({ up: '1.0 MiB', down: '0 B' })
    // peer b comes back on a new connection that already carries traffic
    expect(await tick(wrapper, instance([
      { id: 'a', tx: 1 * GiB + 4 * MiB, rx: 1 * GiB },
      { id: 'b2', tx: 3 * GiB, rx: 3 * GiB },
    ]))).toEqual({ up: '1.0 MiB', down: '0 B' })
  })

  it('never reports a negative rate when a counter goes backwards', async () => {
    const wrapper = await render(instance([{ id: 'a', tx: 5 * GiB, rx: 5 * GiB }]))
    await tick(wrapper)

    expect(await tick(wrapper, instance([{ id: 'a', tx: 1 * MiB, rx: 2 * MiB }])))
      .toEqual({ up: '0 B', down: '0 B' })
    expect(await tick(wrapper, instance([{ id: 'a', tx: 3 * MiB, rx: 2 * MiB }])))
      .toEqual({ up: '1.0 MiB', down: '0 B' })
  })

  it('starts over when the selected network instance changes', async () => {
    const wrapper = await render(instance([{ id: 'a', tx: 1 * MiB, rx: 1 * MiB }]))
    await tick(wrapper)

    const other = '00000000-0000-0000-0000-000000000002'
    expect(await tick(wrapper, instance([{ id: 'a', tx: 9 * GiB, rx: 9 * GiB }], other)))
      .toEqual({ up: '0 B', down: '0 B' })
    expect(await tick(wrapper, instance([{ id: 'a', tx: 9 * GiB + 2 * MiB, rx: 9 * GiB }], other)))
      .toEqual({ up: '1.0 MiB', down: '0 B' })
  })

  it('divides by the time that actually passed between samples', async () => {
    const wrapper = await render(instance([{ id: 'a', tx: 0, rx: 0 }]))
    await tick(wrapper)

    // a background tab can delay the timer: 60 s pass before the next sample
    vi.setSystemTime(Date.now() + 58_000)
    expect(await tick(wrapper, instance([{ id: 'a', tx: 60 * MiB, rx: 0 }])))
      .toEqual({ up: '1.0 MiB', down: '0 B' })
  })
})
