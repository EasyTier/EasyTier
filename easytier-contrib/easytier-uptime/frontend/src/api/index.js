import axios from 'axios'

// 创建axios实例
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
api.interceptors.request.use(
  config => {
    // 只在管理员相关的API请求中添加token
    if (config.url && config.url.includes('/api/admin/')) {
      const token = localStorage.getItem('admin_token')
      if (token) {
        config.headers.Authorization = `Bearer ${token}`
      }
    }
    return config
  },
  error => {
    return Promise.reject(error)
  }
)

// 响应拦截器
api.interceptors.response.use(
  response => {
    // 直接返回完整的response对象，让各个API方法自己处理数据格式
    return response
  },
  error => {
    console.error('API Error Details:', {
      message: error.message,
      status: error.response?.status,
      statusText: error.response?.statusText,
      data: error.response?.data,
      config: {
        url: error.config?.url,
        method: error.config?.method,
        headers: error.config?.headers
      }
    })
    return Promise.reject(error)
  }
)

// 节点相关API
export const nodeApi = {
  // 获取节点列表
  async getNodes(params = {}) {
    const response = await api.get('/api/nodes', { params })
    return response.data
  },

  // 创建节点
  async createNode(data) {
    const response = await api.post('/api/nodes', data)
    return response.data
  },

  // 获取单个节点
  async getNode(id) {
    const response = await api.get(`/api/nodes/${id}`)
    return response.data
  },

  // 更新节点
  async updateNode(id, data) {
    const response = await api.put(`/api/nodes/${id}`, data)
    return response.data
  },

  // 删除节点
  async deleteNode(id) {
    const response = await api.delete(`/api/nodes/${id}`)
    return response.data
  },

  // 获取节点健康记录
  async getNodeHealth(id, params = {}) {
    const response = await api.get(`/api/nodes/${id}/health`, { params })
    return response.data
  },

  // 获取节点健康统计
  async getNodeHealthStats(id, params = {}) {
    const response = await api.get(`/api/nodes/${id}/health/stats`, { params })
    return response.data
  },

  // 测试节点连接
  async testConnection(data) {
    const response = await api.post('/api/test_connection', data)
    return response.data
  }
}

// 健康检查API
export const healthApi = {
  async check() {
    const response = await api.get('/health')
    return response.data
  }
}

// 管理员API
export const adminApi = {
  // 管理员登录
  async login(password) {
    const response = await api.post('/api/admin/login', { password })
    return response.data
  },

  // 验证token有效性
  async verifyToken() {
    const response = await api.get('/api/admin/verify')
    return response.data
  },

  // 获取所有节点（包括未审批的）
  async getNodes(params = {}) {
    const response = await api.get('/api/admin/nodes', { params })
    return response.data
  },

  // 审批节点
  async approveNode(id) {
    const response = await api.put(`/api/admin/nodes/${id}/approve`)
    return response.data
  },

  // 撤销审批节点
  async revokeApproval(id) {
    const response = await api.put(`/api/admin/nodes/${id}/revoke`)
    return response.data
  },

  // 删除节点
  async deleteNode(id) {
    const response = await api.delete(`/api/admin/nodes/${id}`)
    return response.data
  },

  // 更新节点
  async updateNode(id, data) {
    const response = await api.put(`/api/admin/nodes/${id}`, data)
    return response.data
  }
}

export default api