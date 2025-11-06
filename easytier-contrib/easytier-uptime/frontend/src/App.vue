<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { healthApi } from './api'
import {
  Monitor,
  Plus,
  CircleCheck,
  CircleClose,
  Loading,
  Link
} from '@element-plus/icons-vue'

const router = useRouter()
const route = useRoute()
const healthStatus = ref(null)
const loading = ref(false)

// 安全地打开外部链接
const openExternalLink = (url) => {
  try {
    if (typeof window !== 'undefined' && window.open) {
      window.open(url, '_blank')
    } else {
      // 备用方案：创建一个临时链接元素
      const link = document.createElement('a')
      link.href = url
      link.target = '_blank'
      link.rel = 'noopener noreferrer'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    }
  } catch (error) {
    console.error('Failed to open external link:', error)
    // 最后的备用方案：直接跳转
    if (typeof window !== 'undefined') {
      window.location.href = url
    }
  }
}

// 检查后端健康状态
const checkHealth = async () => {
  try {
    loading.value = true
    const response = await healthApi.check()
    healthStatus.value = response.success
  } catch (error) {
    healthStatus.value = false
    console.error('Health check failed:', error)
  } finally {
    loading.value = false
  }
}

// 导航菜单项
const menuItems = [
  {
    path: '/',
    name: 'dashboard',
    title: '节点监控',
    icon: 'Monitor'
  },
  {
    path: '/submit',
    name: 'submit',
    title: '提交节点',
    icon: 'Plus'
  }
]

// 根据当前路由计算默认激活的菜单项
const activeMenuIndex = computed(() => {
  const p = route.path
  if (p.startsWith('/submit')) return 'submit'
  return 'dashboard'
})

// 处理菜单选择，避免返回 Promise 导致异步补丁问题
const handleMenuSelect = (key) => {
  const item = menuItems.find((i) => i.name === key)
  if (item && item.path) {
    router.push(item.path)
  }
}
onMounted(() => {
  checkHealth()
  // 定期检查健康状态
  setInterval(checkHealth, 60000) // 每分钟检查一次
})
</script>

<template>
  <div id="app">
    <!-- 顶部导航栏 -->
    <el-header class="app-header">
      <div class="header-content">
        <div class="logo-section">
          <el-icon size="32" color="#409EFF">
            <Monitor />
          </el-icon>
          <h1 class="app-title">EasyTier Uptime</h1>
        </div>

        <el-menu :default-active="activeMenuIndex" mode="horizontal" class="nav-menu"
          @select="handleMenuSelect">
          <el-menu-item v-for="item in menuItems" :key="item.name" :index="item.name">
            <el-icon>
              <component :is="item.icon" />
            </el-icon>
            <span>{{ item.title }}</span>
          </el-menu-item>
        </el-menu>

        <div class="header-actions">
          <!-- 健康状态指示器 -->
          <el-tooltip :content="healthStatus === null ? '检查中...' : healthStatus ? '服务正常' : '服务异常'" placement="bottom">
            <div class="health-indicator">
              <el-icon :color="healthStatus === null ? '#909399' : healthStatus ? '#67C23A' : '#F56C6C'"
                :class="{ 'loading': loading }">
                <CircleCheck v-if="healthStatus === true" />
                <CircleClose v-else-if="healthStatus === false" />
                <Loading v-else />
              </el-icon>
            </div>
          </el-tooltip>

          <!-- 管理员入口 -->
          <el-button type="warning" link @click="() => router.push('/admin/login')">
            管理员
          </el-button>

          <!-- GitHub链接 -->
          <el-button type="primary" link @click="() => openExternalLink('https://github.com/EasyTier/EasyTier')">
            <el-icon>
              <Link />
            </el-icon>
            GitHub
          </el-button>
        </div>
      </div>
    </el-header>

    <!-- 主要内容区域 -->
    <el-main class="app-main">
      <router-view v-slot="{ Component }">
        <transition name="fade" mode="out-in">
          <component :is="Component" />
        </transition>
      </router-view>
    </el-main>

    <!-- 底部信息 -->
    <el-footer class="app-footer">
      <div class="footer-content">
        <p>
          © 2024 EasyTier Community |
          <el-button type="primary" link size="small"
            @click="() => openExternalLink('https://github.com/EasyTier/EasyTier')">
            开源项目
          </el-button>
          |
          <el-button type="primary" link size="small"
            @click="() => openExternalLink('https://github.com/EasyTier/EasyTier/blob/main/README.md')">
            使用文档
          </el-button>
        </p>
      </div>
    </el-footer>
  </div>
</template>

<style>
/* 全局样式重置 */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', '微软雅黑', Arial, sans-serif;
  background-color: #f5f7fa;
}

#app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

/* 顶部导航栏 */
.app-header {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
  padding: 0;
  height: 60px;
  line-height: 60px;
}

.header-content {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 20px;
}

.logo-section {
  display: flex;
  align-items: center;
  gap: 12px;
}

.app-title {
  color: white;
  font-size: 20px;
  font-weight: 600;
  margin: 0;
}

.nav-menu {
  background: transparent;
  border: none;
  flex: 1;
  justify-content: center;
}

.nav-menu .el-menu-item {
  color: rgba(255, 255, 255, 0.8);
  border-bottom: 2px solid transparent;
  transition: all 0.3s;
}

.nav-menu .el-menu-item:hover,
.nav-menu .el-menu-item.is-active {
  color: white;
  background: rgba(255, 255, 255, 0.1);
  border-bottom-color: white;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 15px;
}

.health-indicator {
  display: flex;
  align-items: center;
  cursor: pointer;
}

.health-indicator .loading {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }

  to {
    transform: rotate(360deg);
  }
}

/* 主要内容区域 */
.app-main {
  flex: 1;
  padding: 0;
  background-color: #f5f7fa;
}

/* 页面切换动画 */
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* 底部信息 */
.app-footer {
  background: white;
  border-top: 1px solid #e4e7ed;
  text-align: center;
  height: 50px;
  line-height: 50px;
}

.footer-content p {
  color: #909399;
  font-size: 14px;
  margin: 0;
}

/* 响应式设计 */
@media (max-width: 768px) {
  .header-content {
    padding: 0 10px;
  }

  .app-title {
    font-size: 16px;
  }

  .nav-menu {
    display: none;
  }

  .header-actions {
    gap: 10px;
  }
}

/* Element Plus 组件样式覆盖 */
.el-card {
  border-radius: 8px;
  box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

.el-button {
  border-radius: 6px;
}

.el-input {
  border-radius: 6px;
}

.el-select {
  border-radius: 6px;
}
</style>
