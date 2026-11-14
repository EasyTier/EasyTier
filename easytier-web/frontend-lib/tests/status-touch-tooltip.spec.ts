import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import PrimeVue from 'primevue/config'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import Status from '../src/components/Status.vue'
import type { NetworkInstance } from '../src/types/network'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

const wrappers: VueWrapper[] = []
const copyText = vi.fn(async (_text: string) => {})

function instance(): NetworkInstance {
  return {
    instance_id: '12345678-9abc-def0-fedc-ba9876543210', running: true,
    detail: {
      my_node_info: { peer_id: 1, hostname: 'local-node', version: 'test' },
      peer_route_pairs: [
        { route: { peer_id: 2, hostname: 'remote-node', cost: 1, version: 'test' },
          peer: { conns: [{ tunnel: { remote_addr: { url: 'tcp://remote:11010' } } }] } },
        { route: { peer_id: 3, hostname: 'server-node', cost: 2, version: 'test',
          feature_flag: { is_public_server: true } } },
      ],
    },
  } as NetworkInstance
}

async function render() {
  const wrapper = mount(Status, {
    props: { curNetworkInst: instance(), api: { get_network_config: vi.fn(async () => ({})) } as any, copyText },
    global: {
      plugins: [PrimeVue],
      directives: { tooltip: {
        beforeMount(el: HTMLElement, binding: { value: { content: string, triggers: string[] } }) {
          updateTooltip(el, binding.value)
        },
        updated(el: HTMLElement, binding: { value: { content: string, triggers: string[] } }) {
          updateTooltip(el, binding.value)
        },
      } },
      stubs: { HumanEvent: true, NetworkChart: true, VpnPortalDialog: true },
    },
  })
  wrappers.push(wrapper)
  await flushPromises()
  return wrapper
}

function updateTooltip(el: HTMLElement, value: { content: string, triggers: string[] }) {
  el.dataset.tooltipContent = value.content
  el.dataset.tooltipTriggers = value.triggers.join(',')
}

const shownTooltip = () => document.querySelector<HTMLElement>('.status-touch-tooltip')

async function touchStart(hostname: ReturnType<VueWrapper['find']>, x = 10, y = 10) {
  await hostname.trigger('touchstart', { touches: [{ clientX: x, clientY: y }] })
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(1000)
  vi.spyOn(window, 'matchMedia').mockImplementation(() => ({ matches: true }) as MediaQueryList)
  copyText.mockClear()
})

afterEach(() => {
  wrappers.splice(0).forEach(wrapper => wrapper.unmount())
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('status hostname long press', () => {
  it('opens selectable tooltip only after a 500 ms press', async () => {
    const wrapper = await render()
    const hostname = wrapper.findAll('[data-status-hostname]')[1]
    expect(hostname.attributes('data-tooltip-content')).toBe('remote-node(tcp://remote:11010)')
    expect(hostname.attributes('data-tooltip-triggers')).toBe('hover,focus')
    await touchStart(hostname)
    await vi.advanceTimersByTimeAsync(499)
    expect(shownTooltip()).toBeNull()
    await vi.advanceTimersByTimeAsync(1)
    await wrapper.vm.$nextTick()
    expect(shownTooltip()?.textContent?.trim()).toBe('remote-node(tcp://remote:11010)')
    await hostname.trigger('touchend')
    expect(shownTooltip()).not.toBeNull()
    expect(copyText).not.toHaveBeenCalled()
  })

  it('cancels on short tap, movement, or touch cancellation', async () => {
    vi.mocked(window.matchMedia).mockImplementation(() => ({ matches: false }) as MediaQueryList)
    const wrapper = await render()
    const hostname = wrapper.findAll('[data-status-hostname]')[1]
    expect(hostname.attributes('data-tooltip-triggers')).toBe('')
    await touchStart(hostname)
    await hostname.trigger('touchend')
    await vi.advanceTimersByTimeAsync(500)
    expect(shownTooltip()).toBeNull()
    await touchStart(hostname)
    await hostname.trigger('touchmove', { touches: [{ clientX: 10, clientY: 40 }] })
    await vi.advanceTimersByTimeAsync(500)
    expect(shownTooltip()).toBeNull()
    await touchStart(hostname)
    await hostname.trigger('touchcancel')
    await vi.advanceTimersByTimeAsync(500)
    expect(shownTooltip()).toBeNull()
    expect(copyText).not.toHaveBeenCalled()
  })

  it('keeps the popper open while selecting text and closes on an outside tap', async () => {
    const wrapper = await render()
    const hostname = wrapper.findAll('[data-status-hostname]')[1]
    await touchStart(hostname)
    await vi.advanceTimersByTimeAsync(500)
    await wrapper.vm.$nextTick()
    const popper = shownTooltip()!
    popper.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    await wrapper.vm.$nextTick()
    expect(shownTooltip()).toBe(popper)
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    await wrapper.vm.$nextTick()
    expect(shownTooltip()).toBeNull()
  })

  it('works on server tags and clears the tooltip when the network changes', async () => {
    const wrapper = await render()
    const hostname = wrapper.findAll('[data-status-hostname]')[2]
    await touchStart(hostname)
    await vi.advanceTimersByTimeAsync(500)
    expect(hostname.attributes('data-tooltip-content')).toBe('server-node')
    expect(shownTooltip()?.textContent?.trim()).toBe('server-node')
    await wrapper.setProps({ curNetworkInst: { ...instance(), instance_id: 'another-network' } })
    expect(shownTooltip()).toBeNull()
  })

  it('preserves mouse double-click copy and ignores a synthetic touch dblclick', async () => {
    const wrapper = await render()
    const hostname = wrapper.findAll('[data-status-hostname]')[1]
    await hostname.trigger('dblclick')
    await flushPromises()
    expect(copyText).toHaveBeenCalledWith('remote-node(tcp://remote:11010)')
    copyText.mockClear()
    await touchStart(hostname)
    await hostname.trigger('touchend')
    await hostname.trigger('dblclick')
    expect(copyText).not.toHaveBeenCalled()
  })

  it('uses the default connection and tolerates an omitted remote address', async () => {
    const network = instance()
    const pair = network.detail!.peer_route_pairs![0]
    pair.peer!.default_conn_id = { part1: 1, part2: 0, part3: 0, part4: 0 }
    pair.peer!.conns = [
      { conn_id: 'other', tunnel: { remote_addr: { url: 'tcp://other:1' } } },
      { conn_id: '00000001-0000-0000-0000-000000000000', tunnel: {
        resolved_remote_addr: { url: 'tcp://resolved:2' },
      } },
    ] as typeof pair.peer.conns
    const wrapper = await render()
    await wrapper.setProps({ curNetworkInst: network })
    const hostname = wrapper.findAll('[data-status-hostname]')[1]
    expect(hostname.text()).toBe('remote-node(tcp://resolved:2)')
    await hostname.trigger('dblclick')
    await flushPromises()
    expect(copyText).toHaveBeenCalledWith('remote-node(tcp://resolved:2)')
  })
})
