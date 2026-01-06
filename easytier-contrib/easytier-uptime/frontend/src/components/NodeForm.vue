<template>
  <div>
    <el-form ref="formRef" :model="form" :rules="rules" label-width="120px" label-position="left"
      @submit.prevent="handleSubmit">
      <el-form-item label="节点名称" prop="name" required>
        <el-input v-model="form.name" placeholder="请输入节点名称，如：北京-联通-01" maxlength="100" show-word-limit clearable>
          <template #prefix>
            <el-icon>
              <Monitor />
            </el-icon>
          </template>
        </el-input>
        <div class="form-tip">建议使用地区-运营商-编号的格式命名</div>
      </el-form-item>

      <el-row :gutter="20">
        <el-col :span="16">
          <el-form-item label="主机地址" prop="host" required>
            <el-input v-model="form.host" placeholder="请输入IP地址或域名" clearable>
              <template #prefix>
                <el-icon>
                  <Location />
                </el-icon>
              </template>
            </el-input>
          </el-form-item>
        </el-col>
        <el-col :span="8">
          <el-form-item label="端口" prop="port" required>
            <el-input-number v-model="form.port" :min="1" :max="65535" placeholder="端口号" style="width: 100%" />
          </el-form-item>
        </el-col>
      </el-row>

      <el-form-item label="协议类型" prop="protocol" required>
        <el-radio-group v-model="form.protocol">
          <el-radio value="tcp">TCP</el-radio>
          <el-radio value="udp">UDP</el-radio>
          <el-radio value="ws">WebSocket</el-radio>
          <el-radio value="wss">WebSocket Secure</el-radio>
        </el-radio-group>
        <div class="form-tip">选择节点支持的连接协议</div>
      </el-form-item>

      <el-form-item label="允许中转" prop="allow_relay" required>
        <el-radio-group v-model="form.allow_relay">
          <el-radio :value="true">允许中转数据</el-radio>
          <el-radio :value="false">仅用于打洞</el-radio>
        </el-radio-group>
        <div class="form-tip">选择节点是否允许中转其他用户的数据流量</div>
      </el-form-item>

      <el-form-item label="网络名称" prop="network_name" required>
        <el-input v-model="form.network_name" placeholder="请输入EasyTier网络名称" maxlength="100" clearable>
          <template #prefix>
            <el-icon>
              <Connection />
            </el-icon>
          </template>
        </el-input>
        <div class="form-tip">与 EasyTier 的 network name 一致，用于后端探活</div>
      </el-form-item>

      <el-form-item label="网络密码" prop="network_secret" required>
        <el-input v-model="form.network_secret" type="password" placeholder="请输入网络密码" maxlength="100" clearable
          show-password>
          <template #prefix>
            <el-icon>
              <Lock />
            </el-icon>
          </template>
        </el-input>
        <div class="form-tip">与 EasyTier 的 network secret 一致</div>
      </el-form-item>

      <el-form-item label="最大网络数" prop="max_connections" required>
        <el-input-number v-model="form.max_connections" :min="1" :max="10000" placeholder="最大网络数量"
          style="width: 200px" />
        <div class="form-tip">节点能够承载的最大网络数量</div>
      </el-form-item>

      <el-form-item label="节点描述" prop="description">
        <el-input v-model="form.description" type="textarea" :rows="4" placeholder="请描述您的节点特点，如：地理位置、网络质量、使用限制等"
          maxlength="500" show-word-limit />
        <div class="form-tip">详细描述有助于用户选择合适的节点</div>
      </el-form-item>

      <!-- 新增：标签管理（仅在管理员编辑时显示） -->
      <el-form-item v-if="props.showTags" label="标签" prop="tags">
        <el-select v-model="form.tags" multiple filterable allow-create default-first-option :multiple-limit="10"
          placeholder="输入后按回车添加，如：北京、联通、IPv6、高带宽">
          <el-option v-for="opt in (form.tags || [])" :key="opt" :label="opt" :value="opt" />
        </el-select>
        <div class="form-tip">用于分类与检索，建议 1-6 个标签，每个不超过 32 字符</div>
      </el-form-item>

      <!-- 联系方式 -->
      <el-form-item label="联系方式" prop="contact_info">
        <div class="contact-section">
          <el-form-item label="微信" prop="wechat">
            <el-input v-model="form.wechat" placeholder="请输入微信号" maxlength="50" clearable>
              <template #prefix>
                <el-icon>
                  <ChatDotRound />
                </el-icon>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="QQ" prop="qq_number">
            <el-input v-model="form.qq_number" placeholder="请输入QQ号" maxlength="20" clearable>
              <template #prefix>
                <el-icon>
                  <User />
                </el-icon>
              </template>
            </el-input>
          </el-form-item>

          <el-form-item label="邮箱" prop="mail">
            <el-input v-model="form.mail" placeholder="请输入邮箱地址" maxlength="100" clearable>
              <template #prefix>
                <el-icon>
                  <Message />
                </el-icon>
              </template>
            </el-input>
          </el-form-item>

          <div class="form-tip">请至少填写一种联系方式，便于节点问题时联系您（仅管理员可见）</div>
        </div>
      </el-form-item>

      <!-- 连接测试 -->
      <el-form-item label="连接测试">
        <div class="test-section">
          <el-button type="warning" @click="testConnection" :loading="testing" :disabled="!canTest">
            <el-icon>
              <Connection />
            </el-icon>
            测试连接
          </el-button>
          <div v-if="testResult" class="test-result">
            <el-tag :type="testResult.success ? 'success' : 'danger'" size="large">
              {{ testResult.success ? '连接成功' : '连接失败' }}
            </el-tag>
            <span v-if="testResult.message" class="test-message">
              {{ testResult.message }}
            </span>
          </div>
        </div>
        <div class="form-tip">建议在提交前测试连接以确保节点可用</div>
      </el-form-item>

      <!-- 使用条款 -->
      <el-form-item prop="agreed" v-if="props.showAgreement">
        <el-checkbox v-model="form.agreed">
          我已阅读并同意
          <el-button type="primary" link @click="showTerms = true">
            《节点共享协议》
          </el-button>
        </el-checkbox>
      </el-form-item>

      <!-- 提交按钮 -->
      <el-form-item>
        <div class="submit-section">
          <el-button type="primary" size="large" @click="handleSubmit" :loading="submitting"
            :disabled="!form.agreed && props.showAgreement">
            <el-icon>
              <Upload />
            </el-icon>
            提交节点
          </el-button>
          <el-button size="large" @click="resetFields">
            <el-icon>
              <RefreshLeft />
            </el-icon>
            重置表单
          </el-button>
        </div>
      </el-form-item>
    </el-form> <!-- 使用条款对话框 -->

    <el-dialog v-model="showTerms" title="节点共享协议" width="600px">
      <div class="terms-content">
        <h3>1. 节点共享原则</h3>
        <p>• 节点提供者应确保节点的稳定性和可用性</p>
        <p>• 不得利用共享节点进行违法违规活动</p>
        <p>• 尊重其他用户的使用权益</p>

        <h3>2. 服务质量要求</h3>
        <p>• 节点应保持7x24小时稳定运行</p>
        <p>• 网络延迟应控制在合理范围内</p>
        <p>• 及时处理连接问题和故障</p>

        <h3>3. 数据安全</h3>
        <p>• 不得记录或泄露用户传输数据</p>
        <p>• 保护用户隐私和数据安全</p>
        <p>• 遵守相关法律法规</p>

        <h3>4. 免责声明</h3>
        <p>• 平台不对节点服务质量承担责任</p>
        <p>• 用户使用节点服务的风险自担</p>
        <p>• 平台有权移除不符合要求的节点</p>
      </div>

      <template #footer>
        <el-button @click="showTerms = false">关闭</el-button>
        <el-button type="primary" @click="acceptTerms">同意并关闭</el-button>
      </template>
    </el-dialog>

  </div>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import {
  Monitor,
  Location,
  PriceTag,
  Connection,
  Upload,
  Edit,
  RefreshLeft,
  ChatDotRound,
  User,
  Message
} from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { nodeApi } from '../api'

const props = defineProps({
  modelValue: {
    type: Object,
    default: () => ({
      name: '',
      host: '',
      port: 11010,
      protocol: 'tcp',
      allow_relay: true,
      network_name: '',
      network_secret: '',
      max_connections: 100,
      description: '',
      wechat: '',
      qq_number: '',
      mail: '',
      tags: [],
      agreed: false
    })
  },
  submitting: {
    type: Boolean,
    default: false
  },
  submitText: {
    type: String,
    default: '提交节点'
  },
  submitIcon: {
    type: String,
    default: 'Upload'
  },
  showConnectionTest: {
    type: Boolean,
    default: true
  },
  showAgreement: {
    type: Boolean,
    default: true
  },
  showCancel: {
    type: Boolean,
    default: false
  },
  // 新增：是否显示标签管理
  showTags: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['update:modelValue', 'submit', 'reset', 'cancel', 'show-terms'])

const formRef = ref()
const testing = ref(false)
const testResult = ref(null)
const showTerms = ref(false)

// 表单数据
const form = reactive({ ...props.modelValue })

// 监听props变化，更新表单数据
watch(() => props.modelValue, (newValue) => {
  Object.assign(form, newValue)
}, { deep: true })

// 监听表单变化，向上传递
watch(form, (newValue) => {
  emit('update:modelValue', { ...newValue })
}, { deep: true })

// 表单验证规则
const rules = {
  name: [
    { required: true, message: '请输入节点名称', trigger: 'blur' },
    { min: 1, max: 100, message: '节点名称长度应在1-100个字符之间', trigger: 'blur' }
  ],
  host: [
    { required: true, message: '请输入主机地址', trigger: 'blur' },
    { min: 1, max: 255, message: '主机地址长度应在1-255个字符之间', trigger: 'blur' },
    {
      pattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
      message: '请输入有效的IP地址或域名',
      trigger: 'blur'
    }
  ],
  port: [
    { required: true, message: '请输入端口号', trigger: 'blur' },
    { type: 'number', min: 1, max: 65535, message: '端口号应在1-65535之间', trigger: 'blur' }
  ],
  protocol: [
    { required: true, message: '请选择协议类型', trigger: 'change' }
  ],
  max_connections: [
    { required: true, message: '请输入最大连接数', trigger: 'blur' },
    { type: 'number', min: 1, max: 10000, message: '最大连接数应在1-10000之间', trigger: 'blur' }
  ],
  version: [
    { max: 50, message: '版本信息长度不能超过50个字符', trigger: 'blur' }
  ],
  description: [
    { max: 500, message: '描述长度不能超过500个字符', trigger: 'blur' }
  ],
  wechat: [
    { max: 50, message: '微信号长度不能超过50个字符', trigger: 'blur' }
  ],
  qq_number: [
    { max: 20, message: 'QQ号长度不能超过20个字符', trigger: 'blur' },
    { pattern: /^[1-9][0-9]{4,19}$/, message: '请输入有效的QQ号', trigger: 'blur' }
  ],
  mail: [
    { max: 100, message: '邮箱地址长度不能超过100个字符', trigger: 'blur' },
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' }
  ],
  contact_info: [
    {
      validator: (rule, value, callback) => {
        if (!form.wechat && !form.qq_number && !form.mail) {
          callback(new Error('请至少填写一种联系方式'))
        } else {
          callback()
        }
      },
      trigger: 'blur'
    }
  ],
  agreed: [
    {
      validator: (rule, value, callback) => {
        if (!value) {
          callback(new Error('请阅读并同意节点共享协议'))
        } else {
          callback()
        }
      },
      trigger: 'change'
    }
  ],
  // 新增：标签规则（仅在显示标签管理时生效）
  tags: [
    {
      validator: (rule, value, callback) => {
        if (!props.showTags) {
          callback()
          return
        }
        if (!Array.isArray(form.tags)) {
          callback(new Error('标签格式错误'))
          return
        }
        if (form.tags.length > 10) {
          callback(new Error('最多添加 10 个标签'))
          return
        }
        for (const t of form.tags) {
          const s = (t || '').trim()
          if (s.length === 0) {
            callback(new Error('标签不能为空'))
            return
          }
          if (s.length > 32) {
            callback(new Error('每个标签不超过 32 字符'))
            return
          }
        }
        callback()
      },
      trigger: 'change'
    }
  ]
}

// 是否可以测试连接
const canTest = computed(() => {
  return form.host && form.port && form.protocol && form.network_name && form.network_secret
})

const buildDataFromForm = () => {
  const data = {
    name: form.name || 'Test Node',
    host: form.host,
    port: form.port,
    protocol: form.protocol,
    description: form.description || null,
    max_connections: form.max_connections || 100,
    allow_relay: form.allow_relay,
    network_name: form.network_name || null,
    network_secret: form.network_secret || null,
    wechat: form.wechat || null,
    qq_number: form.qq_number || null,
    mail: form.mail || null
  }
  // 仅在管理员编辑时附带标签
  if (props.showTags) {
    data.tags = Array.isArray(form.tags) ? form.tags : []
  }
  return data
}

// 测试连接
const testConnection = async () => {
  if (!canTest.value) {
    ElMessage.warning('请先填写主机地址、端口、协议、网络名称和网络密码')
    return
  }

  testing.value = true
  testResult.value = null

  try {
    // 构建测试数据
    const testData = buildDataFromForm()

    // 调用实际的连接测试API
    const response = await nodeApi.testConnection(testData)

    if (response.success) {
      testResult.value = {
        success: true,
        message: '连接测试成功，节点可正常访问'
      }
      ElMessage.success('连接测试成功')
    } else {
      testResult.value = {
        success: false,
        message: response.error || '连接测试失败'
      }
      ElMessage.error('连接测试失败')
    }
  } catch (error) {
    console.error('连接测试失败:', error)
    testResult.value = {
      success: false,
      message: error.response?.data?.error || '测试过程中发生错误，请检查网络连接'
    }
    ElMessage.error('连接测试失败')
  } finally {
    testing.value = false
  }
}

// 提交表单
const handleSubmit = async () => {
  if (!formRef.value) return

  try {
    const valid = await formRef.value.validate()
    if (!valid) return

    const submitData = buildDataFromForm()

    emit('submit', submitData)
  } catch (error) {
    console.error('表单验证失败:', error)
  }
}

// 重置表单
const resetFields = () => {
  if (formRef.value) {
    formRef.value.resetFields()
  }
  // 重置标签
  if (props.showTags) {
    form.tags = []
  }
  testResult.value = null
  emit('reset')
}

const acceptTerms = () => {
  form.agreed = true
  showTerms.value = false
  ElMessage.success('已同意节点共享协议')
}

// 暴露方法给父组件
defineExpose({
  validate: () => formRef.value?.validate(),
  resetFields: () => formRef.value?.resetFields()
})
</script>

<style scoped>
.form-tip {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}

.test-section {
  display: flex;
  align-items: center;
  gap: 12px;
}

.test-result {
  display: flex;
  align-items: center;
  gap: 8px;
}

.test-message {
  font-size: 12px;
  color: #606266;
}

.submit-section {
  display: flex;
  gap: 12px;
}

.contact-section {
  width: 100%;
}

.contact-section .el-form-item {
  margin-bottom: 16px;
}

.contact-section .el-form-item:last-of-type {
  margin-bottom: 8px;
}

.contact-section .el-form-item__label {
  font-size: 14px;
  color: #606266;
  font-weight: 500;
}
</style>