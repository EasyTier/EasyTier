<script setup lang="ts">
import { Button, Dialog, InputNumber, InputText, Select } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
    placeholder?: string
    protos: { [proto: string]: number }
}>()

const { t } = useI18n()
const url = defineModel<string>({ required: true })
const editing = ref(false)
const container = ref<HTMLElement | null>(null)
const internalCompact = ref(false)

onMounted(() => {
    if (container.value) {
        const observer = new ResizeObserver(entries => {
            for (const entry of entries) {
                internalCompact.value = entry.contentRect.width < 400
            }
        })
        observer.observe(container.value)

        onUnmounted(() => {
            observer.disconnect()
        })
    }
})

const parseUrl = (val: string | null | undefined) => {
    if (!val) {
        return { proto: 'tcp', host: '', port: props.protos['tcp'] || 11010 }
    }
    try {
        const urlObj = new URL(val)
        return {
            proto: urlObj.protocol.replace(':', ''),
            host: urlObj.hostname,
            port: parseInt(urlObj.port) || props.protos[urlObj.protocol.replace(':', '')] || 11010
        }
    } catch (e) {
        // Fallback for incomplete or invalid URLs
        const match = val.match(/^(\w+):\/\/(.*)$/)
        if (match) {
            const proto = match[1]
            const rest = match[2]
            const portMatch = rest.match(/:(\d+)$/)
            return {
                proto,
                host: portMatch ? rest.slice(0, portMatch.index) : rest,
                port: portMatch ? parseInt(portMatch[1]) : (props.protos[proto] || 11010)
            }
        }
        return { proto: 'tcp', host: '', port: 11010 }
    }
}

const internalValue = ref(parseUrl(url.value))

// Sync from external
watch(() => url.value, (newVal) => {
    const parsed = parseUrl(newVal)
    if (parsed.proto !== internalValue.value.proto ||
        parsed.host !== internalValue.value.host ||
        parsed.port !== internalValue.value.port) {
        internalValue.value = parsed
    }
})

// Sync to external
watch(internalValue, (newVal) => {
    const proto = newVal.proto || 'tcp'
    const host = newVal.host || '0.0.0.0'
    const port = newVal.port || props.protos[proto] || 11010
    url.value = `${proto}://${host}:${port}`
}, { deep: true })

const protoOptions = computed(() => Object.keys(props.protos))

const onProtoChange = (newProto: string) => {
    const oldProto = internalValue.value.proto
    const oldDefault = props.protos[oldProto]
    const newDefault = props.protos[newProto]

    if (oldDefault !== undefined && internalValue.value.port === oldDefault && newDefault !== undefined) {
        internalValue.value.port = newDefault
    }
    internalValue.value.proto = newProto
}
</script>

<template>
    <div ref="container" class="w-full">
        <InputGroup v-if="!internalCompact" class="w-full">
            <Select :model-value="internalValue.proto" :options="protoOptions" class="max-w-24"
                @update:model-value="onProtoChange" />
            <InputText v-model="internalValue.host" :placeholder="placeholder || '0.0.0.0'" class="grow" />
            <InputGroupAddon>
                <span style="font-weight: bold">:</span>
            </InputGroupAddon>
            <InputNumber v-model="internalValue.port" :format="false" :min="1" :max="65535" class="max-w-24" fluid />
            <slot name="actions"></slot>
        </InputGroup>

        <div v-else class="flex justify-between items-center p-2 border rounded w-full">
            <span class="truncate mr-2">{{ url }}</span>
            <div class="flex items-center">
                <Button icon="pi pi-pencil" class="p-button-sm p-button-text" @click="editing = true" />
                <slot name="actions"></slot>
            </div>
        </div>

        <Dialog v-model:visible="editing" modal :header="placeholder" :style="{ width: '90vw', maxWidth: '500px' }">
            <div class="flex flex-col gap-4 py-4">
                <div class="flex flex-col gap-2">
                    <label>{{ t('tunnel_proto') }}</label>
                    <Select :model-value="internalValue.proto" :options="protoOptions" class="w-full"
                        @update:model-value="onProtoChange" />
                </div>
                <div class="flex flex-col gap-2">
                    <label>{{ t('web.common.address') || 'Address' }}</label>
                    <InputText v-model="internalValue.host" :placeholder="placeholder || '0.0.0.0'" class="w-full" />
                </div>
                <div class="flex flex-col gap-2">
                    <label>{{ t('port') }}</label>
                    <InputNumber v-model="internalValue.port" :format="false" :min="1" :max="65535" class="w-full" />
                </div>
            </div>
            <template #footer>
                <Button :label="t('web.common.confirm') || 'Done'" icon="pi pi-check" @click="editing = false"
                    autofocus />
            </template>
        </Dialog>
    </div>
</template>

<style scoped>
</style>
