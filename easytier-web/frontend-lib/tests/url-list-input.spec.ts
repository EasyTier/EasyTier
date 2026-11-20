import { mount } from '@vue/test-utils'
import { AutoComplete, Button, Dialog, InputNumber, InputText } from 'primevue'
import PrimeVue from 'primevue/config'
import { describe, expect, it } from 'vitest'
import { defineComponent, nextTick, ref } from 'vue'
import { createI18n } from 'vue-i18n'
import UrlInput from '../src/components/UrlInput.vue'
import UrlListInput from '../src/components/UrlListInput.vue'

function mountUrls(protos: Record<string, number>, options: {
  portlessProtos?: string[]
  defaultUrl?: string
  initialUrls?: string[]
} = {}) {
  const urls = ref(options.initialUrls ?? [])
  const wrapper = mount(defineComponent({
    components: { UrlListInput },
    setup: () => ({ urls, protos, options }),
    template: '<UrlListInput v-model="urls" :protos="protos" v-bind="options" add-label="Add URL" />',
  }), {
    global: {
      plugins: [PrimeVue, createI18n({ legacy: false, locale: 'en', missingWarn: false, fallbackWarn: false })],
    },
  })
  return { wrapper, urls }
}

describe('UrlListInput defaults with the real URL editor', () => {
  it.each([
    { protos: { tcp: 11010, udp: 11010 }, expected: 'tcp://0.0.0.0:11010' },
    { protos: { udp: 22000, tcp: 11010 }, expected: 'tcp://0.0.0.0:11010' },
    { protos: { udp: 22000 }, expected: 'udp://0.0.0.0:22000' },
    { protos: {}, expected: 'tcp://0.0.0.0:11010' },
    { protos: { tcp: 0 }, portlessProtos: [], expected: 'tcp://0.0.0.0:0' },
    { protos: { txt: 0 }, expected: 'txt://0.0.0.0' },
    { protos: { tcp: 0 }, portlessProtos: [], defaultUrl: 'udp://example.com:22000', expected: 'udp://example.com:22000' },
    { protos: { tcp: 11010 }, defaultUrl: 'tcp://:11010', expected: 'tcp://:11010' },
  ])('adds $expected', async ({ protos, expected, ...options }) => {
    const { wrapper, urls } = mountUrls(protos as Record<string, number>, options)
    await wrapper.get('[data-testid="add-url"]').trigger('click')
    expect(urls.value).toEqual([expected])
    wrapper.unmount()
  })

  it('keeps dynamic ports editable and preserves zero and URL paths across edits', async () => {
    const { wrapper, urls } = mountUrls({ tcp: 0, ws: 0 }, { portlessProtos: [] })
    await wrapper.get('[data-testid="add-url"]').trigger('click')
    const editor = wrapper.getComponent(UrlInput)
    expect(editor.getComponent(InputNumber).props('min')).toBe(0)

    await editor.get('input.grow').setValue('127.0.0.1')
    await editor.get('input.grow').trigger('blur')
    expect(urls.value).toEqual(['tcp://127.0.0.1:0'])

    editor.getComponent(AutoComplete).vm.$emit('update:modelValue', 'ws')
    await nextTick()
    await editor.findAll('input.grow')[1].setValue('/tunnel')
    expect(urls.value).toEqual(['ws://127.0.0.1:0/tunnel'])

    editor.getComponent(InputNumber).vm.$emit('update:modelValue', 12345)
    await nextTick()
    expect(urls.value).toEqual(['ws://127.0.0.1:12345/tunnel'])
    editor.getComponent(InputNumber).vm.$emit('update:modelValue', 0)
    await nextTick()
    expect(urls.value).toEqual(['ws://127.0.0.1:0/tunnel'])
    wrapper.unmount()
  })

  it('preserves dynamic ports when confirming the compact editor dialog', async () => {
    const { wrapper, urls } = mountUrls({ tcp: 0 }, { portlessProtos: [] })
    await wrapper.get('[data-testid="add-url"]').trigger('click')
    const editor = wrapper.getComponent(UrlInput)
    const editButton = editor.findAllComponents(Button).find(button => button.props('icon') === 'pi pi-pencil')!
    await editButton.trigger('click')
    const dialog = editor.getComponent(Dialog)
    expect(dialog.getComponent(InputNumber).props('min')).toBe(0)
    const host = dialog.findAllComponents(InputText).find(input => input.props('modelValue') === '0.0.0.0')!
    await host.setValue('127.0.0.1')
    const confirm = dialog.findAllComponents(Button).find(button => button.props('icon') === 'pi pi-check')!
    await confirm.trigger('click')
    expect(urls.value).toEqual(['tcp://127.0.0.1:0'])
    expect(dialog.props('visible')).toBe(false)
    wrapper.unmount()
  })

  it('retains fixed mapped-listener defaults when editing', async () => {
    const { wrapper, urls } = mountUrls({ tcp: 11010, udp: 11010 })
    await wrapper.get('[data-testid="add-url"]').trigger('click')
    const editor = wrapper.getComponent(UrlInput)
    expect(editor.getComponent(InputNumber).props('min')).toBe(1)
    await editor.get('input.grow').setValue('example.com')
    await editor.get('input.grow').trigger('blur')
    expect(urls.value).toEqual(['tcp://example.com:11010'])
    wrapper.unmount()
  })

  it('does not rewrite existing explicit ports or implicit WSS ports', async () => {
    const { wrapper, urls } = mountUrls({ tcp: 0, wss: 0 }, {
      portlessProtos: [],
      initialUrls: ['tcp://0.0.0.0:12010', 'wss://example.com/tunnel'],
    })
    const editors = wrapper.findAllComponents(UrlInput)
    await editors[0].get('input.grow').setValue('127.0.0.1')
    await editors[1].get('input.grow').setValue('other.example.com')
    expect(urls.value).toEqual(['tcp://127.0.0.1:12010', 'wss://other.example.com/tunnel'])
    wrapper.unmount()
  })

  it('keeps portless protocols portless when editing', async () => {
    const { wrapper, urls } = mountUrls({ txt: 0 })
    await wrapper.get('[data-testid="add-url"]').trigger('click')
    const editor = wrapper.getComponent(UrlInput)
    expect(editor.findComponent(InputNumber).exists()).toBe(false)
    await editor.get('input.grow').setValue('example.com')
    expect(urls.value).toEqual(['txt://example.com'])
    wrapper.unmount()
  })
})
