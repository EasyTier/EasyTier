<script setup lang="ts">
import { Button } from 'primevue'
import UrlInput from './UrlInput.vue'

const props = defineProps<{
    protos: { [proto: string]: number }
    addLabel: string
    placeholder?: string
    defaultUrl?: string
}>()

const list = defineModel<string[]>({ required: true })

const addUrl = () => {
    list.value.push(props.defaultUrl || 'tcp://0.0.0.0:11010')
}

const removeUrl = (index: number) => {
    list.value.splice(index, 1)
}
</script>

<template>
    <div class="flex flex-col gap-y-2 w-full">
        <div v-for="(_, index) in list" :key="index" class="flex gap-2 items-center w-full">
            <UrlInput v-model="list[index]" :protos="protos" :placeholder="placeholder">
                <template #actions>
                    <Button icon="pi pi-trash" severity="danger" text rounded @click="removeUrl(index)" />
                </template>
            </UrlInput>
        </div>
        <div class="flex justify-center items-center w-full h-10 border-2 border-dashed border-surface-300 dark:border-surface-600 rounded-lg cursor-pointer hover:border-primary hover:bg-surface-50 dark:hover:bg-surface-800 transition-colors duration-200 gap-2 text-surface-500 dark:text-surface-400"
            @click="addUrl">
            <i class="pi pi-plus text-sm"></i>
            <span class="text-sm font-medium">{{ addLabel }}</span>
        </div>
    </div>
</template>
