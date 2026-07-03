<script setup lang="ts">
import { ref, computed } from 'vue'
import { Button, InputText, InputGroup, Message, Divider } from "primevue"

// 表单数据
const cipherHex = ref('')
const secretKey = ref('test')

// 解密结果
const ip = ref('')
const mask = ref('')
const subnet = ref('')
const rawBytes = ref<number[]>([])
const errorMsg = ref('')
const hasDecrypted = ref(false)

// XOR 解密函数
function xorDecrypt(hex: string, key: string): number[] {
  const result: number[] = []
  const keyLen = key.length
  if (keyLen === 0) return result

  for (let i = 0; i < hex.length; i += 2) {
    const hexByte = hex.substring(i, i + 2)
    if (hexByte.length !== 2) break

    const val = parseInt(hexByte, 16)
    if (isNaN(val)) continue

    const keyChar = key[(i / 2) % keyLen]
    const keyVal = keyChar.charCodeAt(0)
    result.push(val ^ keyVal)
  }
  return result
}

// 执行解密
function doDecrypt() {
  errorMsg.value = ''
  hasDecrypted.value = false
  ip.value = ''
  mask.value = ''
  subnet.value = ''
  rawBytes.value = []

  const hex = cipherHex.value.replace(/\s+/g, '').toUpperCase()
  if (!hex) {
    errorMsg.value = '请输入加密的 Hex 字符串'
    return
  }
  if (!/^[0-9A-F]+$/i.test(hex)) {
    errorMsg.value = '输入包含非法字符，仅允许十六进制字符 (0-9, A-F)'
    return
  }
  if (hex.length % 2 !== 0) {
    errorMsg.value = 'Hex 字符串长度必须为偶数（每 2 个字符代表一个字节）'
    return
  }

  const key = secretKey.value || 'test'
  const bytes = xorDecrypt(hex, key)
  rawBytes.value = bytes

  if (bytes.length < 5) {
    errorMsg.value = `解密结果异常：仅得到 ${bytes.length} 个字节，至少需要 5 个（4 字节 IP + 1 字节掩码）`
    return
  }

  ip.value = `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`
  mask.value = String(bytes[4])
  subnet.value = `${bytes[0]}.${bytes[1]}.${bytes[2]}.0`
  hasDecrypted.value = true
}

// 一键复制
function copyResult(text: string) {
  navigator.clipboard.writeText(text)
}

// 清空
function resetForm() {
  cipherHex.value = ''
  secretKey.value = 'test'
  errorMsg.value = ''
  hasDecrypted.value = false
  ip.value = ''
  mask.value = ''
  subnet.value = ''
  rawBytes.value = []
}

// 字节显示文本
const bytesDisplay = computed(() => {
  if (rawBytes.value.length === 0) return ''
  return rawBytes.value.map((b, i) => {
    const label = i < 4 ? `IP[${i}]` : i === 4 ? '掩码' : `字节${i}`
    return `${label}: ${b}`
  }).join('  |  ')
})
</script>

<template>
  <div class="flex items-start justify-center min-h-screen bg-gray-50 p-4">
    <div class="w-full max-w-2xl bg-white rounded-xl shadow-lg p-6 mt-8">
      <!-- 标题 -->
      <div class="text-center mb-6">
        <h1 class="text-2xl font-bold text-gray-800">🔓 EasyTier 密文解密工具</h1>
        <p class="text-gray-500 text-sm mt-1">XOR 异或解密 — 还原 IP 地址与子网掩码</p>
      </div>

      <Divider />

      <!-- 输入表单 -->
      <div class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">密文 (Hex 字符串)</label>
          <InputGroup>
            <InputText
              v-model="cipherHex"
              placeholder="例如: B3CC766476"
              class="w-full font-mono"
              @keyup.enter="doDecrypt"
            />
            <Button icon="pi pi-times" severity="secondary" @click="cipherHex = ''" />
          </InputGroup>
          <p class="text-xs text-gray-400 mt-1">输入需要解密的十六进制字符串，不区分大小写</p>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">密钥 (Key)</label>
          <InputGroup>
            <InputText
              v-model="secretKey"
              placeholder="默认: test"
              class="w-full"
              @keyup.enter="doDecrypt"
            />
            <Button
              :label="secretKey === 'test' ? '默认' : '重置'"
              severity="secondary"
              @click="secretKey = 'test'"
            />
          </InputGroup>
          <p class="text-xs text-gray-400 mt-1">留空则使用默认密钥 <code class="bg-gray-100 px-1 rounded">test</code></p>
        </div>

        <div class="flex gap-3 pt-2">
          <Button
            label="🚀 解密"
            icon="pi pi-lock-open"
            class="flex-1"
            :disabled="!cipherHex.trim()"
            @click="doDecrypt"
          />
          <Button
            label="清空"
            icon="pi pi-refresh"
            severity="secondary"
            @click="resetForm"
          />
        </div>
      </div>

      <Divider />

      <!-- 错误信息 -->
      <Message
        v-if="errorMsg"
        severity="error"
        :closable="false"
        class="mb-4"
      >
        {{ errorMsg }}
      </Message>

      <!-- 解密结果 -->
      <div v-if="hasDecrypted" class="space-y-3">
        <h2 class="text-lg font-semibold text-green-700 flex items-center gap-2">
          <span>✅ 解密成功</span>
        </h2>

        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div class="flex justify-between items-center">
            <div>
              <span class="text-sm text-blue-600 font-medium">解密 IP</span>
              <div class="text-2xl font-bold text-blue-800 font-mono mt-1">{{ ip }}/{{ mask }}</div>
            </div>
            <Button
              icon="pi pi-copy"
              severity="info"
              text
              rounded
              v-tooltip="'复制 IP/掩码'"
              @click="copyResult(`${ip}/${mask}`)"
            />
          </div>
        </div>

        <div class="bg-green-50 border border-green-200 rounded-lg p-4">
          <div class="flex justify-between items-center">
            <div>
              <span class="text-sm text-green-600 font-medium">推算网段</span>
              <div class="text-2xl font-bold text-green-800 font-mono mt-1">{{ subnet }}/{{ mask }}</div>
            </div>
            <Button
              icon="pi pi-copy"
              severity="success"
              text
              rounded
              v-tooltip="'复制网段'"
              @click="copyResult(`${subnet}/${mask}`)"
            />
          </div>
        </div>

        <div v-if="bytesDisplay" class="bg-gray-100 rounded-lg p-3">
          <div class="text-xs text-gray-500 mb-1">解密字节明细</div>
          <div class="text-sm font-mono text-gray-700">{{ bytesDisplay }}</div>
        </div>

        <div class="text-xs text-gray-400 text-center pt-2">
          原始密文: <code class="bg-gray-100 px-1 rounded">{{ cipherHex }}</code>
          &nbsp;|&nbsp; 密钥: <code class="bg-gray-100 px-1 rounded">{{ secretKey }}</code>
        </div>
      </div>

      <!-- 使用说明 -->
      <Divider />
      <details class="text-sm text-gray-500">
        <summary class="cursor-pointer hover:text-gray-700">📖 解密算法说明</summary>
        <div class="mt-2 space-y-1 text-xs">
          <p>1. 将 Hex 字符串按字节（每 2 字符）拆分</p>
          <p>2. 每个字节与密钥对应字符的 ASCII 码进行 XOR 异或运算（密钥循环使用）</p>
          <p>3. 前 4 个结果字节组成 IP 地址（点分十进制）</p>
          <p>4. 第 5 个结果字节为子网掩码位数</p>
          <p>5. 网段 = IP 的前 3 段 + .0</p>
        </div>
      </details>
    </div>
  </div>
</template>

<style scoped>
code {
  font-family: 'Courier New', Courier, monospace;
}
</style>
