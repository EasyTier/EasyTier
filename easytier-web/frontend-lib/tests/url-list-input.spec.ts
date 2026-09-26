import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { defineComponent, h, nextTick, ref } from 'vue'
import UrlListInput from '../src/components/UrlListInput.vue'

const ButtonStub = defineComponent({
  name: 'Button',
  emits: ['click'],
  setup(_, { slots, emit }) {
    return () => h('button', { onClick: (event: MouseEvent) => emit('click', event) }, slots.default?.())
  },
})

const UrlInputStub = defineComponent({
  name: 'UrlInput',
  setup(_, { slots }) {
    return () => h('div', slots.actions?.())
  },
})

function mountUrlListInput(protos: Record<string, number>, defaultUrl?: string) {
  const urls = ref<string[]>([])
  const wrapper = mount(defineComponent({
    components: { UrlListInput },
    setup() {
      return { urls, protos, defaultUrl }
    },
    template: `
      <UrlListInput
        v-model="urls"
        :protos="protos"
        :default-url="defaultUrl"
        add-label="add_url"
      />
    `,
  }), {
    global: {
      stubs: {
        Button: ButtonStub,
        UrlInput: UrlInputStub,
      },
    },
  })

  return { wrapper, urls }
}

describe('UrlListInput.vue add fallback', () => {
  it('derives the fallback URL from protos when defaultUrl is not provided', async () => {
    const { wrapper, urls } = mountUrlListInput({ tcp: 11010, udp: 11010 })

    await wrapper.find('.cursor-pointer').trigger('click')
    await nextTick()

    expect(urls.value).toEqual(['tcp://0.0.0.0:11010'])
  })

  it('falls back to the first available protocol when tcp is not present', async () => {
    const { wrapper, urls } = mountUrlListInput({ udp: 22000 })

    await wrapper.find('.cursor-pointer').trigger('click')
    await nextTick()

    expect(urls.value).toEqual(['udp://0.0.0.0:22000'])
  })

  it('falls back to tcp default port when protos is empty', async () => {
    const { wrapper, urls } = mountUrlListInput({})

    await wrapper.find('.cursor-pointer').trigger('click')
    await nextTick()

    expect(urls.value).toEqual(['tcp://0.0.0.0:11010'])
  })

  it('supports port-zero fallback from protos', async () => {
    const { wrapper, urls } = mountUrlListInput({ tcp: 0, udp: 0 })

    await wrapper.find('.cursor-pointer').trigger('click')
    await nextTick()

    expect(urls.value).toEqual(['tcp://0.0.0.0:0'])
  })

  it('uses defaultUrl when provided', async () => {
    const { wrapper, urls } = mountUrlListInput({ tcp: 11010 }, 'udp://0.0.0.0:22000')

    await wrapper.find('.cursor-pointer').trigger('click')
    await nextTick()

    expect(urls.value).toEqual(['udp://0.0.0.0:22000'])
  })
})
