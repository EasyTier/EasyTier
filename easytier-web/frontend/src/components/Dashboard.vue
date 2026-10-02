<script setup lang="ts">
import { Button, Message, Skeleton } from 'primevue';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { Utils } from 'easytier-frontend-lib';
import ApiClient, { type Summary, type CentralNetworkSummary } from '../modules/api';

const props = defineProps<{ api: ApiClient; centralEnabled: boolean }>();
const { t } = useI18n();
const summary = ref<Summary>();
const devices = ref<Utils.DeviceInfo[]>();
const networks = ref<CentralNetworkSummary[]>();
const loadError = ref(false);
const refreshing = ref(false);

const loadSummary = async () => {
    if (refreshing.value) return;
    refreshing.value = true;
    const results = await Promise.allSettled([
        props.api.get_summary().then(value => { summary.value = value; }),
        props.api.list_machines().then(value => { devices.value = value.map(Utils.buildDeviceInfo); }),
        ...(props.centralEnabled ? [props.api.list_networks().then(value => { networks.value = value; })] : []),
    ]);
    loadError.value = results.some(result => result.status === 'rejected');
    refreshing.value = false;
};
watch(() => props.centralEnabled, () => loadSummary());
const periodFunc = new Utils.PeriodicTask(loadSummary, 2000);
onMounted(() => periodFunc.start());
onUnmounted(() => periodFunc.stop());

const devicePreview = computed(() => [...(devices.value ?? [])]
    .sort((a, b) => ((a.alias || a.hostname) ?? '').localeCompare((b.alias || b.hostname) ?? '')).slice(0, 5));
const networkPreview = computed(() => [...(networks.value ?? [])]
    .sort((a, b) => a.display_name.localeCompare(b.display_name)).slice(0, 5));
const stats = computed(() => [
    { label: 'device_count', note: 'device_note', icon: 'pi-server', value: summary.value?.device_count },
    { label: 'online_device_count', note: 'online_device_note', icon: 'pi-check-circle', value: devices.value?.filter(device => device.online).length },
    ...(props.centralEnabled ? [{ label: 'network_count', note: 'network_note', icon: 'pi-globe', value: networks.value?.length }] : []),
    { label: 'instance_count', note: 'instance_note', icon: 'pi-share-alt', value: devices.value?.reduce((sum, device) => sum + device.running_network_count, 0) },
]);
</script>

<template>
    <div class="console-page">
        <header class="page-heading">
            <div><h1>{{ t('web.main.dashboard') }}</h1></div>
            <Button icon="pi pi-refresh" :label="t('web.console.refresh')" severity="secondary" outlined :loading="refreshing" @click="loadSummary" />
        </header>
        <Message v-if="loadError" severity="warn" :closable="false">{{ t('web.console.load_failed') }}</Message>
        <section class="console-panel summary-strip" :aria-label="t('web.main.dashboard')">
            <div v-for="stat in stats" :key="stat.label" class="summary-stat">
                <div class="summary-label"><span>{{ t(`web.console.${stat.label}`) }}</span><i :class="['pi', stat.icon]" aria-hidden="true"></i></div>
                <div class="summary-value">
                    <Skeleton v-if="stat.value === undefined && !loadError" width="4rem" height="2.8rem" />
                    <template v-else>{{ stat.value ?? '—' }}</template>
                </div>
                <p class="summary-note">{{ t(`web.console.${stat.note}`) }}</p>
            </div>
        </section>
        <div class="overview-columns">
            <section class="console-panel">
                <header class="section-heading"><h2>{{ t('web.main.device_list') }}</h2>
                    <RouterLink :to="{ name: 'deviceList' }" class="entity-link text-xs">{{ t('web.console.view_all') }}<i class="pi pi-arrow-right" aria-hidden="true"></i></RouterLink>
                </header>
                <div v-if="devices === undefined && !loadError" class="loading-rows"><Skeleton v-for="i in 3" :key="i" height="2rem" /></div>
                <div v-else-if="devices?.length === 0" class="console-empty-state">
                    <i class="pi pi-server" aria-hidden="true"></i><h2>{{ t('web.console.devices_empty') }}</h2><p>{{ t('web.console.devices_empty_hint') }}</p>
                    <a href="https://easytier.cn" target="_blank" rel="noopener noreferrer" class="entity-link">{{ t('web.console.documentation') }}<i class="pi pi-arrow-up-right" aria-hidden="true"></i></a>
                </div>
                <RouterLink v-for="device in devicePreview" :key="device.machine_id" class="preview-row"
                    :to="{ name: 'deviceManagement', params: { deviceId: device.machine_id, instanceId: device.running_network_instances?.[0] } }">
                    <div class="entity-link"><i class="pi pi-server entity-icon" aria-hidden="true"></i><div class="min-w-0"><div class="preview-name">{{ device.alias || device.hostname || device.machine_id }}</div><div class="preview-secondary mono-value">{{ device.public_ip || '—' }}</div></div></div>
                    <div class="preview-number">{{ device.running_network_count }}<div class="preview-secondary">{{ t('web.console.instances') }}</div></div>
                </RouterLink>
            </section>
            <section v-if="centralEnabled" class="console-panel">
                <header class="section-heading"><h2>{{ t('web.main.network_list') }}</h2>
                    <RouterLink :to="{ name: 'networkList' }" class="entity-link text-xs">{{ t('web.console.view_all') }}<i class="pi pi-arrow-right" aria-hidden="true"></i></RouterLink>
                </header>
                <div v-if="networks === undefined && !loadError" class="loading-rows"><Skeleton v-for="i in 3" :key="i" height="2rem" /></div>
                <div v-else-if="networks?.length === 0" class="console-empty-state">
                    <i class="pi pi-globe" aria-hidden="true"></i><h2>{{ t('web.console.networks_empty') }}</h2><p>{{ t('web.console.networks_empty_hint') }}</p>
                    <RouterLink :to="{ name: 'networkList' }" class="entity-link">{{ t('web.network_list.create') }}<i class="pi pi-arrow-right" aria-hidden="true"></i></RouterLink>
                </div>
                <RouterLink v-for="network in networkPreview" :key="network.network_id" class="preview-row" :to="{ name: 'networkDetail', params: { networkId: network.network_id } }">
                    <div class="entity-link"><i class="pi pi-globe entity-icon" aria-hidden="true"></i><div class="min-w-0"><div class="preview-name">{{ network.display_name }}</div><div class="preview-secondary">{{ network.network_name }}</div></div></div>
                    <div class="preview-number">{{ network.online_member_count }} / {{ network.member_count }}<div class="preview-secondary">{{ t('web.console.online_members') }}</div></div>
                </RouterLink>
            </section>
        </div>
        <p class="page-footnote"><i class="pi pi-sync" aria-hidden="true"></i>{{ t('web.console.automatic_refresh') }}</p>
    </div>
</template>
