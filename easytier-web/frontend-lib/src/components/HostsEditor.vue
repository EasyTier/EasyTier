<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button, Dialog, InputText, Textarea, ToggleButton } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import type { HostsEntry } from '../generated/proto/api_manage'

const { t } = useI18n()

const hosts = defineModel('hosts', {
  type: Object as () => Record<string, HostsEntry>,
  default: () => ({}),
})

interface HostsRow {
  ip: string
  domains: string[]
  key: string
}

const rows = ref<HostsRow[]>([])

function loadRows() {
  const entries = Object.entries(hosts.value || {})
  rows.value = entries.map(([ip, entry]) => {
    const domains = entry?.domains ? [...entry.domains] : ['']
    return {
      ip,
      domains,
      key: `${ip}:${domains.join(',')}`,
    }
  })
  if (rows.value.length === 0) {
    addRow()
  }
}

function saveRows() {
  const result: Record<string, HostsEntry> = {}
  for (const row of rows.value) {
    const ip = row.ip.trim()
    if (!ip) continue
    const domains = row.domains.filter((d) => d.trim().length > 0)
    if (domains.length > 0) {
      result[ip] = { domains }
    }
  }
  hosts.value = result
}

watch(hosts, loadRows, { immediate: true, deep: true })

function addRow() {
  rows.value.push({ ip: '', domains: [''], key: `new:${Date.now()}` })
}

function removeRow(index: number) {
  rows.value.splice(index, 1)
  saveRows()
}

function updateDomain(index: number, domainIndex: number, value: string) {
  rows.value[index].domains[domainIndex] = value
  saveRows()
}

function addDomain(rowIndex: number) {
  rows.value[rowIndex].domains.push('')
}

function removeDomain(rowIndex: number, domainIndex: number) {
  if (rows.value[rowIndex].domains.length > 1) {
    rows.value[rowIndex].domains.splice(domainIndex, 1)
    saveRows()
  }
}

const rawMode = ref(false)
const rawText = ref('')

function enterRawMode() {
  const lines: string[] = []
  for (const [ip, entry] of Object.entries(hosts.value || {})) {
    const domains = entry?.domains ?? []
    for (const domain of domains) {
      lines.push(`${ip} ${domain}`)
    }
  }
  rawText.value = lines.join('\n')
  rawMode.value = true
}

function saveRawMode() {
  const result: Record<string, HostsEntry> = {}
  const domainsByIp: Record<string, Set<string>> = {}

  for (const line of rawText.value.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const spaceIdx = trimmed.search(/\s+/)
    if (spaceIdx === -1) continue
    const ip = trimmed.slice(0, spaceIdx).trim()
    const domain = trimmed.slice(spaceIdx).trim()
    if (!ip || !domain) continue
    if (!domainsByIp[ip]) {
      domainsByIp[ip] = new Set()
    }
    domainsByIp[ip].add(domain)
  }

  for (const [ip, domains] of Object.entries(domainsByIp)) {
    result[ip] = { domains: [...domains] }
  }

  hosts.value = result
  rawMode.value = false
}

function cancelRawMode() {
  rawMode.value = false
}
</script>

<template>
  <div class="flex flex-col gap-y-3">
    <div class="flex items-center gap-2">
      <ToggleButton v-model="rawMode" on-icon="pi pi-table" off-icon="pi pi-pencil"
        :on-label="t('hosts.raw_mode')" :off-label="t('hosts.visual_mode')" class="w-48"
        @change="rawMode && enterRawMode()" />
      <Button icon="pi pi-plus" :label="t('hosts.add_entry')" severity="secondary" size="small"
        @click="addRow" />
    </div>

    <!-- 可视化模式 -->
    <div v-if="!rawMode" class="flex flex-col gap-y-2">
      <div v-for="(row, rowIndex) in rows" :key="row.key"
        class="flex flex-col gap-2 rounded border border-surface-200 dark:border-surface-700 p-3">
        <div class="flex items-center gap-2">
          <div class="flex flex-col gap-1 grow basis-4/12">
            <label :for="`hosts_ip_${rowIndex}`" class="text-sm font-medium">
              {{ t('hosts.ip_address') }}
            </label>
            <InputText :id="`hosts_ip_${rowIndex}`" v-model="row.ip"
              :placeholder="t('hosts.ip_placeholder')" @blur="saveRows" />
          </div>
          <div class="flex flex-col gap-1 grow basis-6/12">
            <label class="text-sm font-medium">{{ t('hosts.domains') }}</label>
            <InputGroup>
              <InputText v-model="row.domains[0]"
                :placeholder="t('hosts.domain_placeholder')"
                @blur="updateDomain(rowIndex, 0, row.domains[0])" />
              <Button v-if="row.domains.length <= 1" icon="pi pi-plus" severity="secondary" text rounded
                :aria-label="t('hosts.add_domain')" @click="addDomain(rowIndex)" />
              <Button v-else icon="pi pi-minus" severity="secondary" text rounded
                :aria-label="t('hosts.remove_domain')" @click="removeDomain(rowIndex, row.domains.length - 1)" />
            </InputGroup>
            <div v-for="(_, di) in row.domains.slice(1)" :key="di" class="mt-1">
              <InputGroup>
                <InputText v-model="row.domains[di + 1]"
                  :placeholder="t('hosts.domain_placeholder')"
                  @blur="updateDomain(rowIndex, di + 1, row.domains[di + 1])" />
                <Button icon="pi pi-minus" severity="danger" text rounded
                  :aria-label="t('hosts.remove_domain')" @click="removeDomain(rowIndex, di + 1)" />
              </InputGroup>
            </div>
          </div>
          <Button icon="pi pi-trash" severity="danger" text rounded
            :aria-label="t('hosts.remove_entry')" class="self-end" @click="removeRow(rowIndex)" />
        </div>
      </div>
    </div>

    <!-- 原始文本模式 -->
    <div v-else class="flex flex-col gap-2">
      <div class="text-sm text-surface-500 dark:text-surface-400">
        {{ t('hosts.raw_help') }}
      </div>
      <Textarea v-model="rawText" class="font-mono" rows="10" spellcheck="false" />
    </div>
  </div>
</template>
