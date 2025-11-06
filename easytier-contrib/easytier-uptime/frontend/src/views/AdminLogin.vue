<template>
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <div class="login-icon">
          <el-icon :size="48" color="#409EFF">
            <Lock />
          </el-icon>
        </div>
        <h2 class="login-title">管理员登录</h2>
        <p class="login-subtitle">请输入管理员密码以访问管理面板</p>
      </div>

      <div class="login-form">
        <el-form @submit.prevent="handleLogin" :model="form" :rules="rules" ref="loginForm">
          <el-form-item prop="password">
            <el-input v-model="form.password" type="password" placeholder="请输入管理员密码" size="large" show-password
              :prefix-icon="Lock" @keyup.enter="handleLogin" />
          </el-form-item>

          <el-form-item v-if="error">
            <el-alert :title="error" type="error" :closable="false" show-icon />
          </el-form-item>

          <el-form-item>
            <el-button type="primary" size="large" :loading="loading" @click="handleLogin" class="login-button">
              {{ loading ? '登录中...' : '登录' }}
            </el-button>
          </el-form-item>
        </el-form>

        <div class="login-divider">
          <el-divider>或</el-divider>
        </div>

        <div class="login-actions">
          <el-button size="large" @click="$router.push('/')" class="back-button">
            <el-icon class="mr-2">
              <ArrowLeft />
            </el-icon>
            返回首页
          </el-button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { adminApi } from '../api'
import { Lock, ArrowLeft } from '@element-plus/icons-vue'

export default {
  name: 'AdminLogin',
  components: {
    Lock,
    ArrowLeft
  },
  data() {
    return {
      loading: false,
      error: '',
      form: {
        password: ''
      },
      rules: {
        password: [
          { required: true, message: '请输入密码', trigger: 'blur' },
          { min: 1, message: '密码不能为空', trigger: 'blur' }
        ]
      }
    }
  },
  methods: {
    async handleLogin() {
      if (!this.form.password) {
        this.error = '请输入密码'
        return
      }

      this.loading = true
      this.error = ''

      try {
        const response = await adminApi.login(this.form.password)

        // 保存token
        const token = response.data?.token || response.token
        if (token) {
          localStorage.setItem('admin_token', token)

          // 跳转到管理面板
          this.$router.push('/admin')
        } else {
          throw new Error('No token received from server')
        }
      } catch (error) {
        console.error('Login error:', error)
        console.error('Error details:', {
          message: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          data: error.response?.data
        })

        if (error.response?.status === 401) {
          this.error = '密码错误，请重新输入'
        } else if (error.response?.data?.message) {
          this.error = error.response.data.message
        } else if (error.message) {
          this.error = error.message
        } else {
          this.error = '登录失败，请检查网络连接'
        }
      } finally {
        this.loading = false
      }
    }
  },
  mounted() {
    // 如果已经登录，直接跳转到管理面板
    const token = localStorage.getItem('admin_token')
    if (token) {
      this.$router.push('/admin')
    }
  }
}
</script>

<style scoped>
.login-container {
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.login-card {
  background: white;
  border-radius: 16px;
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
  padding: 40px;
  width: 100%;
  max-width: 400px;
  backdrop-filter: blur(10px);
}

.login-header {
  text-align: center;
  margin-bottom: 32px;
}

.login-icon {
  margin-bottom: 16px;
}

.login-title {
  font-size: 28px;
  font-weight: 600;
  color: var(--text-primary);
  margin: 0 0 8px 0;
}

.login-subtitle {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0;
}

.login-form {
  width: 100%;
}

.login-button {
  width: 100%;
  height: 48px;
  font-size: 16px;
  font-weight: 500;
  border-radius: 8px;
}

.login-divider {
  margin: 24px 0;
}

.login-actions {
  width: 100%;
}

.back-button {
  width: 100%;
  height: 48px;
  font-size: 16px;
  border-radius: 8px;
}

.mr-2 {
  margin-right: 8px;
}

/* 响应式设计 */
@media (max-width: 480px) {
  .login-card {
    padding: 24px;
    margin: 16px;
  }

  .login-title {
    font-size: 24px;
  }
}

/* 动画效果 */
.login-card {
  animation: fadeInUp 0.6s ease-out;
}

@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(30px);
  }

  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Element Plus 组件样式覆盖 */
:deep(.el-input__wrapper) {
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: all 0.3s ease;
}

:deep(.el-input__wrapper:hover) {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

:deep(.el-button) {
  transition: all 0.3s ease;
}

:deep(.el-button:hover) {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(64, 158, 255, 0.3);
}
</style>