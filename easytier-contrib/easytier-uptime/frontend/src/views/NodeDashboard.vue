<template>
  <div class="node-dashboard">
    <!-- 页面头部 -->
    <div class="dashboard-header">
      <h1>EasyTier 节点状态监控</h1>
      <p class="subtitle">实时监控所有共享节点的健康状态和连接信息</p>
    </div>

    <!-- 统计卡片 -->
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <div class="stat-number">{{ totalNodes }}</div>
            <div class="stat-label">总节点数</div>
          </div>
          <el-icon class="stat-icon" color="#409EFF">
            <Monitor />
          </el-icon>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <div class="stat-number">{{ activeNodes }}</div>
            <div class="stat-label">在线节点</div>
          </div>
          <el-icon class="stat-icon" color="#67C23A">
            <CircleCheck />
          </el-icon>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <div class="stat-number">{{ averageLoad }} %</div>
            <div class="stat-label">平均负载</div>
          </div>
          <el-icon class="stat-icon" color="#E6A23C">
            <Link />
          </el-icon>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card class="stat-card">
          <div class="stat-content">
            <div class="stat-number">{{ averageUptime }}%</div>
            <div class="stat-label">平均在线率</div>
          </div>
          <el-icon class="stat-icon" color="#F56C6C">
            <TrendCharts />
          </el-icon>
        </el-card>
      </el-col>
    </el-row>

    <!-- 搜索和筛选 -->
    <el-card class="filter-card">
      <el-row :gutter="20">
        <el-col :span="8">
          <el-input v-model="searchText" placeholder="搜索节点名称、主机地址或描述" prefix-icon="Search" clearable
            @input="handleSearch" />
        </el-col>
        <el-col :span="4">
          <el-select v-model="statusFilter" placeholder="状态筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="在线" value="true" />
            <el-option label="离线" value="false" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-select v-model="protocolFilter" placeholder="协议筛选" clearable @change="handleFilter">
            <el-option label="全部" value="" />
            <el-option label="TCP" value="tcp" />
            <el-option label="UDP" value="udp" />
            <el-option label="WS" value="ws" />
            <el-option label="WSS" value="wss" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button type="primary" @click="refreshData" :loading="loading">
            <el-icon>
              <Refresh />
            </el-icon>
            刷新
          </el-button>
        </el-col>
        <el-col :span="4">
          <el-button type="success" @click="$router.push('/submit')">
            <el-icon>
              <Plus />
            </el-icon>
            提交节点
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- 节点列表 -->
    <el-card class="nodes-card">
      <template #header>
        <div class="card-header">
          <span>节点列表</span>
          <el-tag :type="loading ? 'info' : 'success'">
            {{ loading ? '加载中...' : `共 ${pagination.total} 个节点` }}
          </el-tag>
        </div>
      </template>

      <el-table :data="nodes" v-loading="loading" stripe style="width: 100%" row-key="id">
        <!-- 展开列 -->
        <el-table-column type="expand" width="50">
          <template #default="{ row }">
            <div class="expanded-content">
              <HealthTimeline :node-info="row" :compact="true" />
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="name" label="节点名称" width="150">
          <template #default="{ row }">
            <div class="node-name">
              <el-icon :color="row.is_active ? '#67C23A' : '#F56C6C'">
                <CircleCheck v-if="row.is_active" />
                <CircleClose v-else />
              </el-icon>
              <span>{{ row.name }}</span>
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="address" label="节点连接地址" width="250">
          <template #header>
            <span>节点连接地址</span>
            <el-tooltip content="可以将节点链接填入命令行的 -p 参数，或者图形界面的节点地址字段（公共服务器或手动皆可）" placement="top" effect="light">
              <el-icon class="help-icon">
                <QuestionFilled />
              </el-icon>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <el-tag type="primary" size="" style="margin-bottom: 0.2rem;"
              @click="copyAddress(apiUrl + 'node/' + row.id)"> {{
                apiUrl
              }}node/{{ row.id }}</el-tag>
            <el-tag type="info" size="" @click="copyAddress(row.address)">{{ row.address }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="版本" width="90">
          <template #default="{ row }">
            <div style="display: flex; flex-direction: column; gap: 1px; align-items: flex-start;">
              <el-tag v-if="row.version" size="small" style="font-size: 11px; padding: 1px 4px;">{{ row.version
                }}</el-tag>
              <span v-else class="text-muted" style="font-size: 11px;">未知</span>
              <el-tag :type="row.allow_relay ? 'success' : 'info'" size="small"
                style="font-size: 9px; padding: 1px 3px;">
                {{ row.allow_relay ? '可中转' : '禁中转' }}
              </el-tag>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="连接状态" width="150">
          <template #default="{ row }">
            <div class="connection-info">
              <span>{{ row.current_connections }}/{{ row.max_connections }}</span>
              <el-progress :percentage="row.usage_percentage" :color="getProgressColor(row.usage_percentage)"
                :stroke-width="6" :show-text="false" />
            </div>
          </template>
        </el-table-column>

        <el-table-column prop="description" label="描述" min-width="200">
          <template #default="{ row }">
            <span class="description">{{ row.description || '暂无描述' }}</span>
          </template>
        </el-table-column>

        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>

        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }">
            <el-button type="primary" size="small" @click.stop="viewNodeDetails(row)">
              详情
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-wrapper">
        <el-pagination v-model:current-page="pagination.page" v-model:page-size="pagination.per_page"
          :page-sizes="[10, 20, 50, 100]" :total="pagination.total" layout="total, sizes, prev, pager, next, jumper"
          @size-change="handleSizeChange" @current-change="handleCurrentChange" />
      </div>
    </el-card>

    <!-- 节点详情对话框 -->
    <el-dialog v-model="detailDialogVisible" :title="selectedNode?.name + ' - 详细信息'" width="800px" destroy-on-close>
      <div v-if="selectedNode" class="node-details">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="节点名称">{{ selectedNode.name }}</el-descriptions-item>
          <el-descriptions-item label="状态">
            <el-tag :type="selectedNode.is_active ? 'success' : 'danger'">
              {{ selectedNode.is_active ? '在线' : '离线' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="主机地址">{{ selectedNode.host }}</el-descriptions-item>
          <el-descriptions-item label="端口">{{ selectedNode.port }}</el-descriptions-item>
          <el-descriptions-item label="协议">{{ selectedNode.protocol.toUpperCase() }}</el-descriptions-item>
          <el-descriptions-item label="版本">{{ selectedNode.version || '未知' }}</el-descriptions-item>
          <el-descriptions-item label="允许中转">
            <el-tag :type="selectedNode.allow_relay ? 'success' : 'info'" size="small">
              {{ selectedNode.allow_relay ? '是' : '否' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="使用率">{{ selectedNode.usage_percentage.toFixed(1) }}%</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ formatDate(selectedNode.created_at) }}</el-descriptions-item>
          <el-descriptions-item label="更新时间">{{ formatDate(selectedNode.updated_at) }}</el-descriptions-item>
          <el-descriptions-item label="描述" :span="2">{{ selectedNode.description || '暂无描述' }}</el-descriptions-item>
        </el-descriptions>

        <!-- 健康状态统计 -->
        <div class="health-stats" v-if="healthStats">
          <h3>健康状态统计 (最近24小时)</h3>
          <el-row :gutter="20">
            <el-col :span="6">
              <div class="health-stat-item">
                <div class="stat-value">{{ healthStats.uptime_percentage?.toFixed(1) || 0 }}%</div>
                <div class="stat-label">在线率</div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="health-stat-item">
                <div class="stat-value">{{ (selectedNode.last_response_time / 1000) || 0 }}ms</div>
                <div class="stat-label">平均响应时间</div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="health-stat-item">
                <div class="stat-value">{{ healthStats.total_checks || 0 }}</div>
                <div class="stat-label">检查次数</div>
              </div>
            </el-col>
            <el-col :span="6">
              <div class="health-stat-item">
                <div class="stat-value">{{ healthStats.failed_checks || 0 }}</div>
                <div class="stat-label">失败次数</div>
              </div>
            </el-col>
          </el-row>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { nodeApi } from '../api'
import dayjs from 'dayjs'
import HealthTimeline from '../components/HealthTimeline.vue'
import {
  Monitor,
  CircleCheck,
  CircleClose,
  Link,
  TrendCharts,
  Search,
  Refresh,
  Plus
} from '@element-plus/icons-vue'

// 响应式数据
const loading = ref(false)
const nodes = ref([])
const searchText = ref('')
const statusFilter = ref('')
const protocolFilter = ref('')
const detailDialogVisible = ref(false)
const selectedNode = ref(null)
const healthStats = ref(null)
const expandedRows = ref([])
const apiUrl = ref(window.location.href)

// 分页数据
const pagination = reactive({
  page: 1,
  per_page: 50,
  total: 0
})

// 计算属性
const totalNodes = computed(() => nodes.value.length)
const activeNodes = computed(() => nodes.value.filter(node => node.is_active).length)
const averageLoad = computed(() =>
  (nodes.value.reduce((sum, node) => sum + node.current_connections, 0) / (nodes.value.length)).toFixed(2)
)
const averageUptime = computed(() => {
  if (nodes.value.length === 0) return 0
  const activeCount = nodes.value.filter(node => node.is_active).length
  return ((activeCount / nodes.value.length) * 100).toFixed(1)
})

// 方法
const fetchNodes = async (with_loading = true) => {
  try {
    if (with_loading) {
      loading.value = true
    }
    const params = {
      page: pagination.page,
      per_page: pagination.per_page
    }

    if (searchText.value) {
      params.search = searchText.value
    }
    if (statusFilter.value !== '') {
      params.is_active = statusFilter.value === 'true'
    }
    if (protocolFilter.value) {
      params.protocol = protocolFilter.value
    }

    const response = await nodeApi.getNodes(params)
    if (response.success && response.data) {
      nodes.value = response.data.items
      pagination.total = response.data.total
    }
  } catch (error) {
    console.error('获取节点列表失败:', error)
    ElMessage.error('获取节点列表失败')
  } finally {
    if (with_loading) {
      loading.value = false
    }
  }
}

const refreshData = () => {
  fetchNodes()
}

const handleSearch = () => {
  pagination.page = 1
  fetchNodes()
}

const handleFilter = () => {
  pagination.page = 1
  fetchNodes()
}

const handleSizeChange = (size) => {
  pagination.per_page = size
  pagination.page = 1
  fetchNodes()
}

const handleCurrentChange = (page) => {
  pagination.page = page
  fetchNodes()
}

const viewNodeDetails = async (node) => {
  selectedNode.value = node
  detailDialogVisible.value = true

  // 获取健康状态统计
  try {
    const response = await nodeApi.getNodeHealthStats(node.id, { hours: 24 })
    if (response.success && response.data) {
      healthStats.value = response.data
    }
  } catch (error) {
    console.error('获取健康状态统计失败:', error)
  }
}

const formatDate = (dateString) => {
  return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
}

const getProgressColor = (percentage) => {
  if (percentage < 50) return '#67C23A'
  if (percentage < 80) return '#E6A23C'
  return '#F56C6C'
}

const copyAddress = (address) => {
  try {
    navigator.clipboard.writeText(address).then(() => {
      ElMessage.success(`地址已复制, ${address}`)
    }).catch(() => {
      ElMessage.error(`复制失败, ${address}`)
    })
  } catch (error) {
    ElMessage.error(`复制失败, ${address}`)
  }
}

// 生命周期
onMounted(() => {
  fetchNodes()

  // 设置定时刷新
  setInterval(() => {
    fetchNodes(false)
  }, 3000) // 每30秒刷新一次
})
</script>

<style scoped>
.node-dashboard {
  padding: 20px;
  background-color: #f5f7fa;
  min-height: 100vh;
}

.dashboard-header {
  text-align: center;
  margin-bottom: 30px;
}

.dashboard-header h1 {
  color: #303133;
  margin-bottom: 10px;
  font-size: 32px;
  font-weight: 600;
}

.subtitle {
  color: #606266;
  font-size: 16px;
  margin: 0;
}

.stats-row {
  margin-bottom: 16px;
}

.stat-card {
  position: relative;
  overflow: hidden;
  height: 100px;
}

.stat-content {
  padding: 0 16px;
  height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}

.stat-number {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
  line-height: 1;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 12px;
  color: #909399;
  margin: 0;
}

.stat-icon {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 28px;
  opacity: 0.3;
}

.filter-card {
  margin-bottom: 20px;
}

.nodes-card {
  background: white;
  border-radius: 8px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.node-name {
  display: flex;
  align-items: center;
  gap: 8px;
}

.address {
  margin-left: 8px;
  font-family: monospace;
}

.connection-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.description {
  color: #606266;
  font-size: 13px;
}

.text-muted {
  color: #C0C4CC;
}

.pagination-wrapper {
  display: flex;
  justify-content: center;
  margin-top: 20px;
}

.node-details {
  padding: 10px 0;
}

.health-stats {
  margin-top: 30px;
  padding-top: 20px;
  border-top: 1px solid #EBEEF5;
}

.health-stats h3 {
  margin-bottom: 20px;
  color: #303133;
}

.health-stat-item {
  text-align: center;
  padding: 15px;
  background: #f8f9fa;
  border-radius: 6px;
}

.health-stat-item .stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #409EFF;
  margin-bottom: 5px;
}

.health-stat-item .stat-label {
  font-size: 12px;
  color: #909399;
}

.expanded-content {
  padding: 16px 24px;
  background-color: #fafafa;
  border-top: 1px solid #ebeef5;
}
</style>
