<script setup lang="ts">
import { Utils } from 'easytier-frontend-lib';

// 定义组件接收的 props
defineProps<{
  device: Utils.DeviceInfo;
  // 可以传入额外的样式类
  containerClass?: string;
}>();

</script>

<template>
  <div :class="['device-details', containerClass]">
    <div class="detail-item hostname">
      <div class="detail-label">Hostname</div>
      <div class="detail-value">{{ device.hostname }}</div>
    </div>
    <div class="detail-item public-ip">
      <div class="detail-label">Public IP</div>
      <div class="detail-value">{{ device.public_ip }}</div>
    </div>
    <div class="detail-item running-networks">
      <div class="detail-label">Running Networks</div>
      <div class="detail-value">{{ device.running_network_count }}</div>
    </div>
    <div class="detail-item last-report">
      <div class="detail-label">Last Report</div>
      <div class="detail-value">{{ device.report_time }}</div>
    </div>
    <div class="detail-item version">
      <div class="detail-label">EasyTier Version</div>
      <div class="detail-value">{{ device.easytier_version }}</div>
    </div>
    <div class="detail-item machine-id">
      <div class="detail-label">Machine ID</div>
      <div class="detail-value">
        <span class="machine-id-value" :title="device.machine_id">{{ device.machine_id }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.device-details {
  display: grid;
  grid-template-columns: 1fr;
  gap: 0.75rem;
}

.detail-item {
  position: relative;
  margin-bottom: 0.5rem;
  border-bottom: 1px solid var(--surface-border, #e9ecef);
  padding-bottom: 0.75rem;
  transition: background-color 0.2s;
}

.detail-item:hover {
  background-color: var(--surface-hover, rgba(245, 247, 250, 0.5));
}

.detail-item:last-child {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.detail-label {
  font-weight: 600;
  color: var(--text-color, #334155);
  margin-bottom: 0.375rem;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
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
}

/* 特定字段的样式 */
.hostname .detail-label::before {
  background-color: #3b82f6; /* 蓝色 */
}

.public-ip .detail-label::before {
  background-color: #10b981; /* 绿色 */
}

.running-networks .detail-label::before {
  background-color: #f59e0b; /* 橙色 */
}

.last-report .detail-label::before {
  background-color: #8b5cf6; /* 紫色 */
}

.version .detail-label::before {
  background-color: #ec4899; /* 粉色 */
}

.machine-id .detail-label::before {
  background-color: #6b7280; /* 灰色 */
}

/* 机器ID特殊样式 */
.machine-id-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.8rem;
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

/* 暗黑模式适配 */
:root.dark .detail-value {
  color: var(--text-color-secondary, #cbd5e1);
}

:root.dark .detail-label {
  color: var(--text-color, #e2e8f0);
}

:root.dark .machine-id-value {
  background-color: var(--surface-ground, #1e293b);
  color: var(--text-color, #f1f5f9);
  border-color: var(--surface-border, #334155);
}
</style>
