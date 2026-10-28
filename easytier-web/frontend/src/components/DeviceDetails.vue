<script setup lang="ts">
import { Utils } from 'easytier-frontend-lib';
import { useI18n } from 'vue-i18n'

const { t } = useI18n()


// 定义组件接收的 props
defineProps<{
  device: Utils.DeviceInfo;
  // 可以传入额外的样式类
  containerClass?: string;
  // 是否使用紧凑布局
  compact?: boolean;
}>();

</script>

<template>
  <div :class="['device-details', containerClass, { 'compact': compact }]">
    <div class="detail-item hostname">
      <div class="detail-label">{{ t('web.device.hostname') }}</div>
      <div class="detail-value">{{ device.hostname }}</div>
    </div>
    <div class="detail-item status">
      <div class="detail-label">{{ t('web.device.status') }}</div>
      <div class="detail-value">{{ device.online ? t('web.device.online') : t('web.device.offline') }}</div>
    </div>
    <div v-if="!device.online && device.last_seen" class="detail-item last-seen">
      <div class="detail-label">{{ t('web.device.last_seen') }}</div>
      <div class="detail-value">{{ device.last_seen }}</div>
    </div>
    <div class="detail-item public-ip">
      <div class="detail-label">{{ t('web.device.public_ip') }}</div>
      <div class="detail-value">{{ device.public_ip }}</div>
    </div>
    <div class="detail-item running-networks">
      <div class="detail-label">{{ t('web.device.networks') }}</div>
      <div class="detail-value">{{ device.running_network_count }}</div>
    </div>
    <div class="detail-item location">
      <div class="detail-label">{{ t('web.console.location') }}</div>
      <div class="detail-value">{{ device.location ? [device.location.country, device.location.region, device.location.city].filter(Boolean).join(' · ') : t('web.device.unknown_location') }}</div>
    </div>
    <div v-if="(device.networks?.length ?? 0) > 0" class="detail-item central-networks">
      <div class="detail-label">{{ t('web.device.central_networks') }}</div>
      <div class="detail-value">
        <span v-for="network in device.networks" :key="network.network_id" class="central-network-name"
          :title="network.network_name">{{ network.display_name }}</span>
      </div>
    </div>
    <div class="detail-item version">
      <div class="detail-label">{{ t('web.device.version') }}</div>
      <div class="detail-value">{{ device.easytier_version }}</div>
    </div>
    <details class="more-details">
      <summary>{{ t('web.console.more_details') }}</summary>
      <div class="detail-item last-report">
        <div class="detail-label">{{ t('web.device.last_report') }}</div>
        <div class="detail-value">{{ device.report_time }}</div>
      </div>
      <div class="detail-item machine-id">
        <div class="detail-label">{{ t('web.device.machine_id') }}</div>
        <div class="detail-value">
          <span class="machine-id-value" :title="device.machine_id">{{ device.machine_id }}</span>
        </div>
      </div>
    </details>
  </div>
</template>

<style scoped>
/* 紧凑布局样式 */
.device-details.compact {
  gap: 0.4rem;
}

.detail-item {
  position: relative;
  transition: all 0.2s;
  border-radius: 0.25rem;
}

.more-details summary {
  cursor: pointer;
  font-size: 12px;
  color: var(--console-muted, #64748b);
  margin-top: 10px;
}

.detail-item:hover {
  background-color: var(--surface-hover, rgba(245, 247, 250, 0.5));
}

.compact .detail-item {
  padding: 0.3rem 0.2rem;
  display: grid;
  grid-template-columns: 40% 60%;
  align-items: center;
}

.detail-label {
  font-weight: 600;
  margin-bottom: 0.375rem;
  display: flex;
  align-items: center;
}

.compact .detail-label {
  margin-bottom: 0;
}

.detail-value {
  color: var(--text-color-secondary, #475569);
  word-break: break-all;
  line-height: 1.4;
}

/* 紧凑布局的值样式 */
.compact .detail-value {
  padding-left: 0.3rem;
  line-height: 1.2;
}

.central-network-name {
  display: inline-block;
  background-color: var(--surface-ground, #f1f5f9);
  border: 1px solid var(--surface-border, #e2e8f0);
  border-radius: 0.25rem;
  padding: 0.05rem 0.4rem;
  margin: 0.1rem 0.2rem 0.1rem 0;
  font-size: 0.85rem;
}

/* 机器ID特殊样式 */
.machine-id-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.95rem;
  background-color: var(--surface-ground, #f1f5f9);
  color: var(--text-color, #1f2937);
  padding: 0.25rem 0.5rem;
  border-radius: 0.25rem;
  border: 1px solid var(--surface-border, #e2e8f0);
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 紧凑布局下的机器ID样式 */
.compact .machine-id-value {
  font-size: 0.75rem;
  padding: 0.15rem 0.3rem;
  border-radius: 0.2rem;
}
</style>
