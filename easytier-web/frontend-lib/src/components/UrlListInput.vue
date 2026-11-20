<script setup lang="ts">
import { Button } from 'primevue'
import UrlInput from './UrlInput.vue'

const props = defineProps<{
    protos: { [proto: string]: number }
    portlessProtos?: string[]
    addLabel: string
    placeholder?: string
    defaultUrl?: string
}>()

const list = defineModel<string[]>({ required: true })

const fallbackUrl = () => {
    const protoKeys = Object.keys(props.protos)
    const proto = protoKeys.includes('tcp') ? 'tcp' : (protoKeys[0] ?? 'tcp')
    const port = props.protos[proto] ?? 11010
    const portless = props.portlessProtos?.includes(proto) ?? props.protos[proto] === 0
    return `${proto}://0.0.0.0${portless ? '' : `:${port}`}`
}

const addUrl = () => {
    list.value.push(props.defaultUrl || fallbackUrl())
}

const removeUrl = (index: number) => {
    list.value.splice(index, 1)
}
</script>

<template>
    <div class="flex flex-col gap-y-2 w-full">
        <div v-for="(_, index) in list" :key="index" class="flex gap-2 items-center w-full">
            <UrlInput v-model="list[index]" :protos="protos" :portless-protos="portlessProtos"
                :placeholder="placeholder">
                <template #actions>
                    <Button icon="pi pi-trash" severity="danger" text rounded @click="removeUrl(index)" />
                </template>
            </UrlInput>
        </div>
        <div class="flex justify-center items-center w-full h-10 border-2 border-dashed border-surface-300 dark:border-surface-600 rounded-lg cursor-pointer hover:border-primary hover:bg-surface-50 dark:hover:bg-surface-800 transition-colors duration-200 gap-2 text-surface-500 dark:text-surface-400"
            data-testid="add-url" @click="addUrl">
            <i class="pi pi-plus text-sm"></i>
            <span class="text-sm font-medium">{{ addLabel }}</span>
        </div>
    </div>
</template>
