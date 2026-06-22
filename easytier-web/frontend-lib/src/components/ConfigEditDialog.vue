<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from 'vue';
import { NetworkConfig } from '../types/network';
import { Divider, Button, Dialog, Textarea } from 'primevue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps({
    readonly: {
        type: Boolean,
        default: false,
    },
    generateConfig: {
        type: Object as () => (config: NetworkConfig) => Promise<string>,
        required: true,
    },
    saveConfig: {
        type: Object as () => (config: string) => Promise<void>,
        required: true,
    },
})

const curNetwork = defineModel('curNetwork', {
    type: Object as () => NetworkConfig | undefined,
    required: true,
})

const refreshTomlConfig = async (config: NetworkConfig | undefined) => {
    if (!config) {
        tomlConfig.value = '';
        return;
    }

    await nextTick();
    const configSnapshot = JSON.parse(JSON.stringify(config)) as NetworkConfig;
    try {
        errorMessage.value = '';
        tomlConfig.value = await props.generateConfig(configSnapshot);
    } catch (e) {
        errorMessage.value = 'Failed to generate config: ' + (e instanceof Error ? e.message : String(e));
        tomlConfig.value = '';
    }
}

const visible = defineModel('visible', {
    type: Boolean,
    default: false,
})
watch([visible, () => curNetwork.value?.instance_id], async ([newVisible]) => {
    if (!newVisible) {
        tomlConfig.value = '';
        return;
    }
    await refreshTomlConfig(curNetwork.value);
})
onMounted(async () => {
    if (!visible.value) {
        return;
    }
    await refreshTomlConfig(curNetwork.value);
});

const handleConfigSave = async () => {
    if (props.readonly) return;
    try {
        await props.saveConfig(tomlConfig.value);
        visible.value = false;
    } catch (e) {
        errorMessage.value = 'Failed to save config: ' + (e instanceof Error ? e.message : String(e));
    }
};

const tomlConfig = ref<string>('')
const tomlConfigRows = ref<number>(1);
const errorMessage = ref<string>('');

watch(tomlConfig, (newValue) => {
    tomlConfigRows.value = newValue.split('\n').length;
    errorMessage.value = '';
});

</script>
<template>
    <Dialog v-model:visible="visible" modal :header="t('config_file')" :style="{ width: '70%' }">
        <pre v-if="errorMessage"
            class="mb-2 p-2 rounded text-sm overflow-auto bg-red-100 text-red-700 max-h-40">{{ errorMessage }}</pre>
        <div class="flex w-full" style="max-height: 60vh; overflow-y: auto;">
            <Textarea v-model="tomlConfig" class="w-full h-full font-mono flex flex-col resize-none" :rows="tomlConfigRows"
                spellcheck="false" :readonly="props.readonly"></Textarea>
        </div>
        <Divider />
        <div class="flex gap-2 justify-end">
            <Button v-if="!props.readonly" type="button" :label="t('save')" @click="handleConfigSave" />
            <Button type="button" :label="t('close')" @click="visible = false" />
        </div>
    </Dialog>
</template>
