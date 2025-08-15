import { createRouter, createWebHistory } from 'vue-router'
import NodeDashboard from '../views/NodeDashboard.vue'
import SubmitNode from '../views/SubmitNode.vue'
import AdminLogin from '../views/AdminLogin.vue'
import AdminDashboard from '../views/AdminDashboard.vue'

const routes = [
  {
    path: '/',
    name: 'Dashboard',
    component: NodeDashboard,
    meta: {
      title: '节点状态监控'
    }
  },
  {
    path: '/submit',
    name: 'Submit',
    component: SubmitNode,
    meta: {
      title: '提交共享节点'
    }
  },
  {
    path: '/admin/login',
    name: 'AdminLogin',
    component: AdminLogin,
    meta: {
      title: '管理员登录'
    }
  },
  {
    path: '/admin',
    name: 'AdminDashboard',
    component: AdminDashboard,
    meta: {
      title: '管理员面板',
      requiresAuth: true
    }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 路由守卫
router.beforeEach(async (to, from, next) => {
  // 设置页面标题
  if (to.meta.title) {
    document.title = `${to.meta.title} - EasyTier Uptime`
  }

  // 检查管理员权限
  if (to.meta.requiresAuth) {
    const token = localStorage.getItem('admin_token')
    if (!token) {
      next('/admin/login')
      return
    }

    // 验证token有效性
    try {
      const { adminApi } = await import('../api')
      await adminApi.verifyToken()
    } catch (error) {
      console.error('Token verification failed:', error)
      localStorage.removeItem('admin_token')
      next('/admin/login')
      return
    }
  }

  next()
})

export default router