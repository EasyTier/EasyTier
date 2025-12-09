<template>
  <div class="health-timeline" :class="{ 'compact': compact }">
    <div class="timeline-header">
      <span class="timeline-title">最近24小时健康状态</span>
      <div class="timeline-legend">
        <span class="legend-item">
          <span class="legend-dot perfect"></span>
          <span class="legend-text">100%</span>
        </span>
        <span class="legend-item">
          <span class="legend-dot excellent"></span>
          <span class="legend-text">90-99%</span>
        </span>
        <span class="legend-item">
          <span class="legend-dot good"></span>
          <span class="legend-text">80-89%</span>
        </span>
        <span class="legend-item">
          <span class="legend-dot fair"></span>
          <span class="legend-text">60-79%</span>
        </span>
        <span class="legend-item">
          <span class="legend-dot poor"></span>
          <span class="legend-text">1-59%</span>
        </span>
        <span class="legend-item">
          <span class="legend-dot unknown"></span>
          <span class="legend-text">未知</span>
        </span>
      </div>
    </div>

    <div class="timeline-container" v-loading="loading">
      <div class="timeline-grid">
        <!-- 时间刻度 -->
        <div class="time-labels">
          <span v-for="(hour, idx) in timeLabels" :key="idx" class="time-label">
            {{ hour }}
          </span>
        </div>

        <!-- 健康状态条 -->
        <div class="health-bars">
          <div v-for="(segment, index) in healthSegments" :key="index" class="health-segment" :class="segment.status"
            :style="{ width: segment.width + '%', backgroundColor: segment.color }" :title="getSegmentTooltip(segment)">
          </div>
        </div>
      </div>

      <!-- 统计信息 -->
      <div class="health-summary">
        <div class="summary-item">
          <span class="summary-value">{{ uptimePercentage }}%</span>
          <span class="summary-label">在线率</span>
        </div>
        <div class="summary-item">
          <span class="summary-value">{{ avgResponseTime }}ms</span>
          <span class="summary-label">平均响应</span>
        </div>
        <div class="summary-item">
          <span class="summary-value">{{ totalChecks }}</span>
          <span class="summary-label">检查次数</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { nodeApi } from '../api'
import dayjs from 'dayjs'

const props = defineProps({
  nodeInfo: {
    type: Object,
    required: true
  },
  compact: {
    type: Boolean,
    default: true
  }
})

const loading = ref(false)
const avg_response_time = ref(0)

// 时间标签（24小时，每4小时一个标签）
const timeLabels = computed(() => {
  const nodeInfo = props.nodeInfo
  const granularity = nodeInfo.ring_granularity
  const total_ring = nodeInfo.health_record_total_counter_ring
  const totalDuration = granularity * total_ring.length
  const now = dayjs(nodeInfo.last_check_time)
  const startTime = now.subtract(totalDuration, 'second')

  const labelCount = 6
  const labelIntervalDuration = totalDuration / (labelCount - 1)

  let labels = []
  for (let i = 0; i < labelCount; i++) {
    const time = startTime.add(i * labelIntervalDuration, 'second')
    labels.push(time.format('HH:mm'))
  }

  return labels
})

const total_checks = computed(() => {
  let total = 0
  for (let i = 0; i < props.nodeInfo.health_record_total_counter_ring.length; i++) {
    total += props.nodeInfo.health_record_total_counter_ring[i]
  }
  return total
})

const healthy_checks = computed(() => {
  let total = 0
  for (let i = 0; i < props.nodeInfo.health_record_healthy_counter_ring.length; i++) {
    total += props.nodeInfo.health_record_healthy_counter_ring[i]
  }
  return total
})

const uptime_percentage = computed(() => {
  return (healthy_checks.value / total_checks.value) * 100
})

// 根据成功率获取颜色
const getColorBySuccessRate = (rate) => {
  if (rate === 1) {
    return '#67c23a' // 100% 绿色
  } else if (rate >= 0.9) {
    return '#85ce61' // 90-99% 浅绿色
  } else if (rate >= 0.8) {
    return '#e6a23c' // 80-89% 橙色
  } else if (rate >= 0.6) {
    return '#f78989' // 60-79% 浅红色
  } else if (rate > 0) {
    return '#f56c6c' // 1-59% 红色
  } else {
    return '#c0c4cc' // 0% 或未知 灰色
  }
}

// 健康状态分段
const healthSegments = computed(() => {
  const nodeInfo = props.nodeInfo
  const total_ring = nodeInfo.health_record_total_counter_ring
  const healthy_ring = nodeInfo.health_record_healthy_counter_ring
  const granularity = nodeInfo.ring_granularity
  const totalDuration = granularity * total_ring.length

  const segments = []
  const now = dayjs(nodeInfo.last_check_time)
  const startTime = now.subtract(totalDuration, 'second')

  for (let i = total_ring.length - 1; i >= 0; i--) {
    const total_counter = total_ring[i]
    const healthy_counter = healthy_ring[i]
    const currentTime = startTime.subtract((i + 1) * granularity, 'second')
    const currentEndTime = currentTime.add(granularity, 'second')

    let successRate = 0
    let currentStatus = 'unknown'

    if (total_counter !== 0) {
      successRate = healthy_counter / total_counter
      if (successRate === 1) {
        currentStatus = 'perfect'
      } else if (successRate >= 0.9) {
        currentStatus = 'excellent'
      } else if (successRate >= 0.8) {
        currentStatus = 'good'
      } else if (successRate >= 0.6) {
        currentStatus = 'fair'
      } else if (successRate > 0) {
        currentStatus = 'poor'
      } else {
        currentStatus = 'failed'
      }
    }

    segments.push({
      status: currentStatus,
      successRate: successRate,
      color: getColorBySuccessRate(successRate),
      width: (granularity / totalDuration) * 100,
      duration: granularity / 60.0,
      startTime: currentTime.format('HH:mm'),
      endTime: currentEndTime.format('HH:mm'),
    })
  }

  return segments
})

// 统计数据
const uptimePercentage = computed(() => {
  return uptime_percentage.value.toFixed(1) || '0.0'
})

const avgResponseTime = computed(() => {
  return (props.nodeInfo.last_response_time / 1000).toFixed(1) || '0.0'
})

const totalChecks = computed(() => {
  return total_checks.value || 0
})

// 获取分段提示信息
const getSegmentTooltip = (segment) => {
  const statusText = {
    perfect: '完美',
    excellent: '优秀',
    good: '良好',
    fair: '一般',
    poor: '较差',
    failed: '失败',
    unknown: '未知'
  }[segment.status] || '未知'

  const successRateText = segment.successRate > 0 ? `${(segment.successRate * 100).toFixed(1)}%` : '0%'

  return `${segment.startTime} - ${segment.endTime}: ${statusText} (${successRateText}) - ${Math.round(segment.duration)}分钟`
}

</script>

<style scoped>
.health-timeline {
  background: #f8f9fa;
  border-radius: 8px;
  padding: 12px;
  margin-top: 8px;
  border: 1px solid #e4e7ed;
}

.timeline-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.timeline-title {
  font-size: 13px;
  font-weight: 500;
  color: #606266;
}

.timeline-legend {
  display: flex;
  gap: 12px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}

.legend-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.legend-dot.perfect {
  background-color: #67c23a;
}

.legend-dot.excellent {
  background-color: #85ce61;
}

.legend-dot.good {
  background-color: #e6a23c;
}

.legend-dot.fair {
  background-color: #f78989;
}

.legend-dot.poor {
  background-color: #f56c6c;
}

.legend-dot.unknown {
  background-color: #c0c4cc;
}

.legend-text {
  font-size: 11px;
  color: #909399;
}

.timeline-container {
  position: relative;
  min-height: 60px;
}

.timeline-grid {
  position: relative;
}

.time-labels {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.time-label {
  font-size: 10px;
  color: #c0c4cc;
  font-family: monospace;
}

.health-bars {
  display: flex;
  height: 12px;
  border-radius: 6px;
  overflow: hidden;
  background-color: #f0f0f0;
  margin-bottom: 8px;
}

.health-segment {
  height: 100%;
  transition: all 0.3s ease;
  cursor: pointer;
}

/* 颜色现在通过动态样式设置，不再需要这些CSS类 */

.health-segment:hover {
  opacity: 0.8;
  transform: scaleY(1.2);
}

.response-time-chart {
  height: 30px;
  margin-bottom: 8px;
}

.response-chart {
  width: 100%;
  height: 100%;
}

.health-summary {
  display: flex;
  justify-content: space-around;
  padding-top: 8px;
  border-top: 1px solid #e4e7ed;
}

.summary-item {
  text-align: center;
}

.summary-value {
  display: block;
  font-size: 14px;
  font-weight: 600;
  color: #409eff;
  line-height: 1;
}

.summary-label {
  font-size: 10px;
  color: #909399;
  margin-top: 2px;
}

/* 紧凑模式 */
.health-timeline.compact {
  padding: 8px;
}

.health-timeline.compact .timeline-header {
  margin-bottom: 8px;
}

.health-timeline.compact .timeline-title {
  font-size: 12px;
}

.health-timeline.compact .health-bars {
  height: 8px;
  margin-bottom: 6px;
}

.health-timeline.compact .health-summary {
  padding-top: 6px;
}

.health-timeline.compact .summary-value {
  font-size: 12px;
}

.health-timeline.compact .summary-label {
  font-size: 9px;
}
</style>