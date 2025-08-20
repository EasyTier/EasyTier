<template>
  <div>
    <el-container class="admin-dashboard">
      <!-- 头部导航 -->
      <el-header class="admin-header">
        <div class="header-content">
          <div class="flex">
            <h1 class="header-title">管理员面板</h1>
          </div>
          <div class="header-actions">
            <router-link to="/" class="nav-link">
              返回首页
            </router-link>
            <el-button type="danger" @click="logout">
              退出登录
            </el-button>
          </div>
        </div>
      </el-header>

      <!-- 主要内容 -->
      <el-main class="main-content">
        <!-- 统计卡片 -->
        <el-row :gutter="20" class="mb-20">
          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon success">
                  <el-icon>
                    <Check />
                  </el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-label">已审批节点</div>
                  <div class="stat-value">{{ stats.approved }}</div>
                </div>
              </div>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon warning">
                  <el-icon>
                    <Clock />
                  </el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-label">待审批节点</div>
                  <div class="stat-value">{{ stats.pending }}</div>
                </div>
              </div>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon info">
                  <el-icon>
                    <DataAnalysis />
                  </el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-label">总节点数</div>
                  <div class="stat-value">{{ stats.total }}</div>
                </div>
              </div>
            </el-card>
          </el-col>

          <el-col :xs="24" :sm="12" :md="6">
            <el-card class="stat-card">
              <div class="stat-content">
                <div class="stat-icon success">
                  <el-icon>
                    <CircleCheck />
                  </el-icon>
                </div>
                <div class="stat-info">
                  <div class="stat-label">在线节点</div>
                  <div class="stat-value">{{ stats.active }}</div>
                </div>
              </div>
            </el-card>
          </el-col>
        </el-row>

        <!-- 筛选器 -->
        <el-card class="mb-20">
          <template #header>
            <span>筛选条件</span>
          </template>
          <el-row :gutter="20">
            <el-col :xs="24" :sm="12" :md="6">
              <el-form-item label="审批状态">
                <el-select v-model="filters.approved" @change="loadNodes" placeholder="全部" clearable>
                  <el-option label="全部" value="" />
                  <el-option label="已审批" value="true" />
                  <el-option label="待审批" value="false" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :xs="24" :sm="12" :md="6">
              <el-form-item label="在线状态">
                <el-select v-model="filters.active" @change="loadNodes" placeholder="全部" clearable>
                  <el-option label="全部" value="" />
                  <el-option label="在线" value="true" />
                  <el-option label="离线" value="false" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :xs="24" :sm="12" :md="6">
              <el-form-item label="协议">
                <el-select v-model="filters.protocol" @change="loadNodes" placeholder="全部" clearable>
                  <el-option label="全部" value="" />
                  <el-option label="TCP" value="tcp" />
                  <el-option label="UDP" value="udp" />
                  <el-option label="WireGuard" value="wg" />
                  <el-option label="WebSocket" value="ws" />
                  <el-option label="WebSocket Secure" value="wss" />
                </el-select>
              </el-form-item>
            </el-col>
            <el-col :xs="24" :sm="12" :md="6">
              <el-form-item label="搜索">
                <el-input v-model="filters.search" @input="debounceSearch" placeholder="搜索节点名称或主机" clearable />
              </el-form-item>
            </el-col>
          </el-row>
        </el-card>

        <!-- 节点列表 -->
        <el-card>
          <template #header>
            <div class="flex-between">
              <div>
                <h3>节点列表</h3>
                <p class="text-secondary">管理所有共享节点</p>
              </div>
            </div>
          </template>

          <div v-if="loading" class="text-center p-20">
            <el-icon class="is-loading" size="32">
              <Loading />
            </el-icon>
            <p class="mt-10">加载中...</p>
          </div>

          <el-table v-else-if="nodes.length > 0" :data="nodes" stripe>
            <el-table-column prop="name" label="节点名称" min-width="120">
              <template #default="{ row }">
                <div class="flex items-center">
                  <el-icon class="mr-2"
                    :color="row.is_active && row.is_approved ? '#67C23A' : !row.is_approved ? '#E6A23C' : '#F56C6C'">
                    <CircleCheck v-if="row.is_active && row.is_approved" />
                    <Clock v-else-if="!row.is_approved" />
                    <el-icon v-else>❌</el-icon>
                  </el-icon>
                  <span>{{ row.name }}</span>
                </div>
              </template>
            </el-table-column>

            <el-table-column prop="host" label="主机地址" min-width="150">
              <template #default="{ row }">
                {{ row.host }}:{{ row.port }}
              </template>
            </el-table-column>

            <el-table-column prop="protocol" label="协议" width="80">
              <template #default="{ row }">
                <el-tag :type="getProtocolType(row.protocol)" size="small">
                  {{ row.protocol.toUpperCase() }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column prop="is_approved" label="审批状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.is_approved ? 'success' : 'warning'" size="small">
                  {{ row.is_approved ? '已审批' : '待审批' }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column prop="is_active" label="在线状态" width="100">
              <template #default="{ row }">
                <el-tag :type="row.is_active ? 'success' : 'danger'" size="small">
                  {{ row.is_active ? '在线' : '离线' }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column prop="description" label="描述" min-width="150" show-overflow-tooltip />

            <el-table-column prop="created_at" label="创建时间" width="160">
              <template #default="{ row }">
                {{ formatDate(row.created_at) }}
              </template>
            </el-table-column>

            <el-table-column label="操作" width="200" fixed="right">
              <template #default="{ row }">
                <el-button type="primary" size="small" @click="editNode(row)">
                  编辑
                </el-button>
                <el-button v-if="!row.is_approved" type="success" size="small" @click="approveNode(row.id)">
                  审批
                </el-button>
                <el-button v-if="row.is_approved" type="warning" size="small" @click="revokeApproval(row.id)">
                  撤销
                </el-button>
                <el-button type="danger" size="small" @click="deleteNode(row.id)">
                  删除
                </el-button>
              </template>
            </el-table-column>
          </el-table>

          <el-empty v-else description="暂无节点数据" />
        </el-card>
      </el-main>
    </el-container>

    <!-- 编辑节点对话框 -->
    <el-dialog v-model="editDialogVisible" title="编辑节点" width="800px" destroy-on-close>
      <NodeForm v-if="editDialogVisible" v-model="editForm" :submitting="updating" submit-text="更新节点" submit-icon="Edit"
        :show-connection-test="false" :show-agreement="false" :show-cancel="true" @submit="handleUpdateNode"
        @cancel="editDialogVisible = false" @reset="resetEditForm" />
    </el-dialog>
  </div>
</template>

<script>
import { adminApi } from '../api'
import dayjs from 'dayjs'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Check, Clock, DataAnalysis, CircleCheck, Loading } from '@element-plus/icons-vue'
import NodeForm from '../components/NodeForm.vue'

export default {
  name: 'AdminDashboard',
  components: {
    Check,
    Clock,
    DataAnalysis,
    CircleCheck,
    Loading,
    NodeForm
  },
  data() {
    return {
      loading: false,
      nodes: [],
      filters: {
        approved: '',
        active: '',
        protocol: '',
        search: ''
      },
      searchTimeout: null,
      editDialogVisible: false,
      editForm: {
        name: '',
        host: '',
        port: 11010,
        protocol: 'tcp',
        version: '',
        max_connections: 100,
        description: ''
      },
      editingNodeId: null,
      updating: false
    }
  },
  computed: {
    stats() {
      const total = this.nodes.length
      const approved = this.nodes.filter(node => node.is_approved).length
      const pending = this.nodes.filter(node => !node.is_approved).length
      const active = this.nodes.filter(node => node.is_active).length

      return {
        total,
        approved,
        pending,
        active
      }
    }
  },
  async mounted() {
    // 先验证token有效性
    try {
      await adminApi.verifyToken()
      await this.loadNodes()
    } catch (error) {
      console.error('Token verification failed in mounted:', error)
      this.logout()
    }
  },
  methods: {
    async loadNodes() {
      try {
        this.loading = true
        const params = {}
        if (this.filters.approved !== '') {
          params.approved = this.filters.approved
        }
        if (this.filters.active !== '') {
          params.active = this.filters.active
        }
        if (this.filters.protocol) {
          params.protocol = this.filters.protocol
        }
        if (this.filters.search) {
          params.search = this.filters.search
        }

        const response = await adminApi.getNodes(params)
        this.nodes = response.data?.items || []
      } catch (error) {
        console.error('加载节点失败:', error)
        if (error.response?.status === 401) {
          this.logout()
        } else {
          ElMessage.error('加载节点失败')
        }
      } finally {
        this.loading = false
      }
    },
    async approveNode(nodeId) {
      try {
        await ElMessageBox.confirm('确定要审批通过这个节点吗？', '确认审批', {
          type: 'warning'
        })
        await adminApi.approveNode(nodeId)
        ElMessage.success('审批成功')
        await this.loadNodes()
      } catch (error) {
        if (error !== 'cancel') {
          console.error('审批失败:', error)
          ElMessage.error('审批失败')
        }
      }
    },
    async revokeApproval(nodeId) {
      try {
        await ElMessageBox.confirm('确定要撤销这个节点的审批吗？撤销后节点将变为待审批状态。', '确认撤销审批', {
          type: 'warning'
        })
        await adminApi.revokeApproval(nodeId)
        ElMessage.success('撤销审批成功')
        await this.loadNodes()
      } catch (error) {
        if (error !== 'cancel') {
          console.error('撤销审批失败:', error)
          ElMessage.error('撤销审批失败')
        }
      }
    },
    async deleteNode(nodeId) {
      try {
        await ElMessageBox.confirm('确定要删除这个节点吗？此操作不可恢复！', '确认删除', {
          type: 'warning'
        })
        await adminApi.deleteNode(nodeId)
        ElMessage.success('删除成功')
        await this.loadNodes()
      } catch (error) {
        if (error !== 'cancel') {
          console.error('删除失败:', error)
          ElMessage.error('删除失败')
        }
      }
    },
    editNode(node) {
      this.editingNodeId = node.id
      this.editForm = node
      this.editDialogVisible = true
    },
    async handleUpdateNode(formData) {
      try {
        this.updating = true
        await adminApi.updateNode(this.editingNodeId, formData)
        ElMessage.success('节点更新成功')
        this.editDialogVisible = false
        await this.loadNodes()
      } catch (error) {
        console.error('更新节点失败:', error)
        ElMessage.error('更新节点失败')
      } finally {
        this.updating = false
      }
    },
    resetEditForm() {
      this.editForm = {
        name: '',
        host: '',
        port: 11010,
        protocol: 'tcp',
        version: '',
        max_connections: 100,
        description: ''
      }
    },
    debounceSearch() {
      if (this.searchTimeout) {
        clearTimeout(this.searchTimeout)
      }
      this.searchTimeout = setTimeout(() => {
        this.loadNodes()
      }, 500)
    },
    formatDate(dateString) {
      return dayjs(dateString).format('YYYY-MM-DD HH:mm:ss')
    },
    getProtocolType(protocol) {
      const typeMap = {
        tcp: 'primary',
        udp: 'success',
        wg: 'warning',
        ws: 'info',
        wss: 'danger'
      }
      return typeMap[protocol] || 'info'
    },
    async logout() {
      try {
        await ElMessageBox.confirm('确定要退出登录吗？', '确认退出', {
          type: 'warning'
        })
        localStorage.removeItem('admin_token')
        this.$router.push('/admin/login')
      } catch (error) {
        // 用户取消
      }
    }
  }
}
</script>

<style scoped>
.admin-dashboard {
  min-height: 100vh;
}

.admin-header {
  background: white;
  border-bottom: 1px solid #e4e7ed;
  padding: 0;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 20px;
  height: 100%;
}

.header-title {
  margin: 0;
  color: #303133;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 16px;
}

.nav-link {
  color: #409eff;
  text-decoration: none;
}

.nav-link:hover {
  color: #66b1ff;
}

.main-content {
  background: #f5f7fa;
  padding: 20px;
}

.mb-20 {
  margin-bottom: 20px;
}

.stat-card {
  position: relative;
  overflow: hidden;
  height: 100px;
}

.stat-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  box-sizing: border-box;
}

.stat-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.stat-label {
  font-size: 12px;
  color: #909399;
  margin: 0 0 4px 0;
}

.stat-value {
  font-size: 24px;
  font-weight: bold;
  color: #303133;
  line-height: 1;
  margin: 0;
}

.stat-icon {
  font-size: 28px;
  opacity: 0.3;
  margin-left: 16px;
}

.stat-icon.success {
  color: #67c23a;
}

.stat-icon.warning {
  color: #e6a23c;
}

.stat-icon.info {
  color: #409eff;
}

.flex {
  display: flex;
}

.flex-between {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.items-center {
  align-items: center;
}

.mr-2 {
  margin-right: 8px;
}

.mt-10 {
  margin-top: 10px;
}

.p-20 {
  padding: 20px;
}

.text-center {
  text-align: center;
}

.text-secondary {
  color: #909399;
}
</style>