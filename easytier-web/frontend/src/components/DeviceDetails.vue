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

const formatMemory = (used?: number, total?: number) => {
  if (used === undefined || total === undefined) return '-';
  // Backend值在实际环境相当于字节，转换为 GiB 以匹配 free -h 直观展示
  const toGiB = (bytes: number) => bytes / 1024 / 1024 / 1024;
  const usedGiB = toGiB(used).toFixed(2);
  const totalGiB = toGiB(total).toFixed(2);
  return `${usedGiB} GiB / ${totalGiB} GiB`;
};

</script>

<template>
  <div :id="`device-details-${device.machine_id}`" :class="['device-details', containerClass, { 'compact': compact }]">
    <div :id="`device-details-${device.machine_id}-hostname`" class="detail-item hostname">
      <div :id="`device-details-${device.machine_id}-hostname-label`" class="detail-label">{{ t('web.device.hostname') }}</div>
      <div :id="`device-details-${device.machine_id}-hostname-value`" class="detail-value">{{ device.hostname }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-public-ip`" class="detail-item public-ip">
      <div :id="`device-details-${device.machine_id}-public-ip-label`" class="detail-label">{{ t('web.device.public_ip') }}</div>
      <div :id="`device-details-${device.machine_id}-public-ip-value`" class="detail-value">{{ device.public_ip }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-networks`" class="detail-item running-networks">
      <div :id="`device-details-${device.machine_id}-networks-label`" class="detail-label">{{ t('web.device.networks') }}</div>
      <div :id="`device-details-${device.machine_id}-networks-value`" class="detail-value">{{ device.running_network_count }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-last-report`" class="detail-item last-report">
      <div :id="`device-details-${device.machine_id}-last-report-label`" class="detail-label">{{ t('web.device.last_report') }}</div>
      <div :id="`device-details-${device.machine_id}-last-report-value`" class="detail-value">{{ device.report_time }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-version`" class="detail-item version">
      <div :id="`device-details-${device.machine_id}-version-label`" class="detail-label">{{ t('web.device.version') }}</div>
      <div :id="`device-details-${device.machine_id}-version-value`" class="detail-value">{{ device.easytier_version }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-os-version`" class="detail-item os-version">
      <div :id="`device-details-${device.machine_id}-os-version-label`" class="detail-label">{{ t('web.device.os_version') }}</div>
      <div :id="`device-details-${device.machine_id}-os-version-value`" class="detail-value">{{ device.os_version || '-' }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-cpu-usage`" class="detail-item cpu-usage">
      <div :id="`device-details-${device.machine_id}-cpu-usage-label`" class="detail-label">{{ t('web.device.cpu_usage') }}</div>
      <div :id="`device-details-${device.machine_id}-cpu-usage-value`" class="detail-value">{{ device.cpu_usage !== undefined ? device.cpu_usage.toFixed(1) + '%' : '-' }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-memory`" class="detail-item memory">
      <div :id="`device-details-${device.machine_id}-memory-label`" class="detail-label">{{ t('web.device.memory') }}</div>
      <div :id="`device-details-${device.machine_id}-memory-value`" class="detail-value">{{ formatMemory(device.mem_used, device.mem_total) }}</div>
    </div>
    <div :id="`device-details-${device.machine_id}-machine-id`" class="detail-item machine-id">
      <div :id="`device-details-${device.machine_id}-machine-id-label`" class="detail-label">{{ t('web.device.machine_id') }}</div>
      <div :id="`device-details-${device.machine_id}-machine-id-value`" class="detail-value">
        <span :id="`device-details-${device.machine_id}-machine-id-text`" class="machine-id-value" :title="device.machine_id">{{ device.machine_id }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* 基础布局 */
.device-details {
  display: grid;
  grid-template-columns: 1fr;
  gap: 0.75rem;
}

/* 标准布局的详情项样式 */
.detail-item {
  position: relative;
  border-bottom: 1px solid var(--surface-border, #e9ecef);
  padding-bottom: 0.75rem;
  transition: all 0.2s;
  border-radius: 0.25rem;
}

.detail-item:hover {
  background-color: var(--surface-hover, rgba(245, 247, 250, 0.5));
}

.detail-item:last-child {
  border-bottom: none;
}

.detail-label {
  font-weight: 600;
  color: var(--text-color, #334155);
  font-size: 0.95rem;
  margin-bottom: 0.375rem;
  display: flex;
  align-items: center;
}

/* 紧凑布局样式 */
.device-details.compact {
  gap: 0.4rem;
}

.compact .detail-item {
  padding: 0.3rem 0.2rem;
  display: grid;
  grid-template-columns: 40% 60%;
  align-items: center;
}

.compact .detail-label {
  margin-bottom: 0;
}

.detail-label::before {
  content: "";
  display: inline-block;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background-color: #3b82f6;
  margin-right: 0.5rem;
}

.detail-value {
  color: var(--text-color-secondary, #475569);
  word-break: break-all;
  padding-left: 1rem;
  line-height: 1.4;
  font-size: 0.95rem;
}

/* 紧凑布局的标签和值样式 */
.compact .detail-label::before {
  width: 3px;
  height: 3px;
  margin-right: 0.3rem;
}

.compact .detail-value {
  padding-left: 0.3rem;
  line-height: 1.2;
}

/* 特定字段的样式 */
.hostname .detail-label::before {
  background-color: #3b82f6;
  /* 蓝色 */
}

.public-ip .detail-label::before {
  background-color: #10b981;
  /* 绿色 */
}

.running-networks .detail-label::before {
  background-color: #f59e0b;
  /* 橙色 */
}

.last-report .detail-label::before {
  background-color: #8b5cf6;
  /* 紫色 */
}

.version .detail-label::before {
  background-color: #ec4899;
  /* 粉色 */
}

.machine-id .detail-label::before {
  background-color: #6b7280;
  /* 灰色 */
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

/* 暗黑模式适配 */
@media (prefers-color-scheme: dark) {
  .detail-item {
    border-bottom: 1px solid var(--surface-border, #334155);
  }

  .detail-item:last-child {
    border-bottom: none;
  }

  .detail-item:hover {
    background-color: var(--surface-hover, rgba(30, 41, 59, 0.4));
  }

  .detail-value {
    color: var(--text-color-secondary, #cbd5e1);
  }

  .detail-label {
    color: var(--text-color, #e2e8f0);
  }

  .machine-id-value {
    background-color: var(--surface-ground, #1e293b);
    color: var(--text-color, #f1f5f9);
    border-color: var(--surface-border, #334155);
  }
}
</style>
