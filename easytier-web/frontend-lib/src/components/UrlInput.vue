<script setup lang="ts">
import { AutoComplete, Button, Dialog, InputNumber, InputText } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { buildUrlInputValue, getHostInputValue, parseHostInputOnBlur, parseUrlInput } from '../modules/url-input'

const props = defineProps<{
    placeholder?: string
    protos: { [proto: string]: number }
}>()

const { t } = useI18n()
const url = defineModel<string>({ required: true })
const editing = ref(false)
const container = ref<HTMLElement | null>(null)
const internalCompact = ref(false)
const hostFocused = ref(false)

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

const internalValue = ref(parseUrlInput(url.value, props.protos))
const defaultHost = '0.0.0.0'

const syncUrlFromInternal = (forceDefaultHost = false) => {
    const nextUrl = buildUrlInputValue(internalValue.value, props.protos, forceDefaultHost)
    if (!nextUrl || nextUrl === url.value) {
        return
    }
    url.value = nextUrl
}

const onHostBlur = () => {
    hostFocused.value = false
    const parsedHost = parseHostInputOnBlur(internalValue.value.host ?? '', internalValue.value.proto, props.protos)
    if (parsedHost) {
        internalValue.value = parsedHost
    }
    syncUrlFromInternal(true)
}

const onHostFocus = () => {
    hostFocused.value = true
}

const onDialogConfirm = () => {
    syncUrlFromInternal(true)
    editing.value = false
}

const isNoPortProto = computed(() => {
    return props.protos[internalValue.value.proto] === 0
})

const hostInputValue = computed({
    get: () => getHostInputValue(internalValue.value),
    set: (value: string) => {
        internalValue.value.host = value
        internalValue.value.suffix = undefined
    },
})

// Sync from external
watch(() => url.value, (newVal) => {
    if (hostFocused.value) {
        return
    }
    const parsed = parseUrlInput(newVal, props.protos)
    const internalHost = internalValue.value.host ?? ''
    const sameHost = parsed.host === internalHost || (!internalHost.trim() && parsed.host === defaultHost)
    if (parsed.proto !== internalValue.value.proto ||
        !sameHost ||
        parsed.port !== internalValue.value.port) {
        internalValue.value = parsed
    }
})

// Sync to external
watch(internalValue, () => {
    if (hostFocused.value) {
        return
    }
    syncUrlFromInternal(false)
}, { deep: true })

const protoOptions = computed(() => Object.keys(props.protos))
const filteredProtos = ref<string[]>([])

const searchProtos = (event: { query: string }) => {
    if (!event.query.trim().length) {
        filteredProtos.value = [...protoOptions.value]
    } else {
        filteredProtos.value = protoOptions.value.filter((proto) => {
            return proto.toLowerCase().startsWith(event.query.toLowerCase())
        })
    }
}

const onProtoChange = (newProto: string) => {
    const oldProto = internalValue.value.proto
    const oldDefault = props.protos[oldProto]
    const newDefault = props.protos[newProto]

    if (oldDefault !== undefined && internalValue.value.port === oldDefault && newDefault !== undefined) {
        internalValue.value.port = newDefault
    }
    internalValue.value.proto = newProto
    internalValue.value.suffix = undefined
    internalValue.value.hasExplicitPort = true
}
</script>

<template>
    <div ref="container" class="w-full">
        <InputGroup v-if="!internalCompact" class="w-full">
            <AutoComplete :model-value="internalValue.proto" :suggestions="filteredProtos" dropdown
                class="max-w-32 proto-autocomplete-in-group" @complete="searchProtos"
                @update:model-value="onProtoChange" />
            <InputText v-model="hostInputValue" :placeholder="placeholder || '0.0.0.0'" class="grow"
                @focus="onHostFocus" @blur="onHostBlur" />
            <template v-if="!isNoPortProto">
                <InputGroupAddon>
                    <span style="font-weight: bold">:</span>
                </InputGroupAddon>
                <InputNumber v-model="internalValue.port" :format="false" :min="1" :max="65535" class="max-w-24"
                    :placeholder="String(protos[internalValue.proto] ?? 11010)"
                    fluid />
            </template>
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
                    <AutoComplete :model-value="internalValue.proto" :suggestions="filteredProtos" dropdown fluid
                        @complete="searchProtos" @update:model-value="onProtoChange" />
                </div>
                <div class="flex flex-col gap-2">
                    <label>{{ t('web.common.address') || 'Address' }}</label>
                    <InputText v-model="hostInputValue" :placeholder="placeholder || '0.0.0.0'" class="w-full"
                        @focus="onHostFocus" @blur="onHostBlur" />
                </div>
                <div v-if="!isNoPortProto" class="flex flex-col gap-2">
                    <label>{{ t('port') }}</label>
                    <InputNumber v-model="internalValue.port" :format="false" :min="1" :max="65535" class="w-full"
                        :placeholder="String(protos[internalValue.proto] ?? 11010)" />
                </div>
            </div>
            <template #footer>
                <Button :label="t('web.common.confirm') || 'Done'" icon="pi pi-check" @click="onDialogConfirm"
                    autofocus />
            </template>
        </Dialog>
    </div>
</template>

<style scoped>
.proto-autocomplete-in-group,
.proto-autocomplete-in-group :deep(.p-autocomplete-input),
.proto-autocomplete-in-group :deep(.p-autocomplete-dropdown) {
    border-top-right-radius: 0 !important;
    border-bottom-right-radius: 0 !important;
}

.proto-autocomplete-in-group :deep(.p-autocomplete-dropdown) {
    border-right: 0 !important;
}
</style>
