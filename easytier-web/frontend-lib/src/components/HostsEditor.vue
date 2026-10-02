<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button, InputText, Textarea, ToggleButton } from 'primevue'
import InputGroup from 'primevue/inputgroup'
import type { HostsConfig } from '../generated/proto/api_manage'

const { t } = useI18n()

const hosts = defineModel('hosts', {
  type: Array as () => HostsConfig[],
  default: () => [],
})

interface HostsRow {
  ip: string
  domains: string[]
  key: string
}

const rows = ref<HostsRow[]>([])

let initialLoad = true

function loadRows() {
  const list: HostsConfig[] = Array.isArray(hosts.value) ? hosts.value : []
  rows.value = list.map((entry, idx) => ({
    ip: entry?.ip ?? '',
    domains: entry?.domains?.length ? [...entry.domains] : [''],
    key: `${entry?.ip ?? ''}:${entry?.domains?.join(',') ?? ''}:${idx}`,
  }))
  if (rows.value.length === 0) {
    addRow()
  }
  if (initialLoad) {
    savedSnapshot.value = JSON.stringify(hosts.value)
    initialLoad = false
  }
}

function saveRows() {
  const result: HostsConfig[] = []
  for (const row of rows.value) {
    const ip = row.ip.trim()
    if (!ip) continue
    const domains = row.domains.filter((d) => d.trim().length > 0)
    if (domains.length > 0) {
      result.push({ ip, domains })
    }
  }
  hosts.value = result
  savedSnapshot.value = JSON.stringify(result)
}

watch(hosts, loadRows, { immediate: true })


const savedSnapshot = ref('')

const hasChanges = computed(() => {
  const current: HostsConfig[] = []
  for (const row of rows.value) {
    const ip = row.ip.trim()
    if (!ip) continue
    const domains = row.domains.filter((d) => d.trim().length > 0)
    if (domains.length > 0) {
      current.push({ ip, domains })
    }
  }
  return JSON.stringify(current) !== savedSnapshot.value
})


function addRow() {
  rows.value.push({ ip: '', domains: [''], key: `new:${Date.now()}` })
}

function removeRow(index: number) {
  rows.value.splice(index, 1)
}

function updateDomain(index: number, domainIndex: number, value: string) {
  rows.value[index].domains[domainIndex] = value
}

function addDomain(rowIndex: number) {
  rows.value[rowIndex].domains.push('')
}

function removeDomain(rowIndex: number, domainIndex: number) {
  if (rows.value[rowIndex].domains.length > 1) {
    rows.value[rowIndex].domains.splice(domainIndex, 1)
  }
}

const rawMode = ref(false)
const rawText = ref('')

function enterRawMode() {
  const lines: string[] = []
  const list: HostsConfig[] = Array.isArray(hosts.value) ? hosts.value : []
  for (const entry of list) {
    for (const domain of entry.domains) {
      lines.push(`${entry.ip} ${domain}`)
    }
  }
  rawText.value = lines.join('\n')
  rawMode.value = true
}

function saveRawMode() {
  const result: HostsConfig[] = []
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
    result.push({ ip, domains: [...domains] })
  }

  hosts.value = result
  savedSnapshot.value = JSON.stringify(result)
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
      <div class="flex items-center gap-2">
        <Button icon="pi pi-save" :label="t('hosts.save')" size="small" :disabled="!hasChanges" @click="saveRows" />
        <span v-if="hasChanges" class="text-xs text-amber-500">{{ '● ' }}</span>
      </div>
      <div v-for="(row, rowIndex) in rows" :key="rowIndex"
        class="flex flex-col gap-2 rounded border border-surface-200 dark:border-surface-700 p-3">
        <div class="flex items-center gap-2">
          <div class="flex flex-col gap-1 grow basis-4/12">
            <label :for="`hosts_ip_${rowIndex}`" class="text-sm font-medium">
              {{ t('hosts.ip_address') }}
            </label>
            <InputText :id="`hosts_ip_${rowIndex}`" v-model="row.ip"
              :placeholder="t('hosts.ip_placeholder')" />
          </div>
          <div class="flex flex-col gap-1 grow basis-6/12">
            <label class="text-sm font-medium">{{ t('hosts.domains') }}</label>
            <InputGroup>
              <InputText v-model="row.domains[0]"
                :placeholder="t('hosts.domain_placeholder')" />
              <Button v-if="row.domains.length <= 1" icon="pi pi-plus" severity="secondary" text rounded
                :aria-label="t('hosts.add_domain')" @click="addDomain(rowIndex)" />
              <Button v-else icon="pi pi-minus" severity="secondary" text rounded
                :aria-label="t('hosts.remove_domain')" @click="removeDomain(rowIndex, row.domains.length - 1)" />
            </InputGroup>
            <div v-for="(_, di) in row.domains.slice(1)" :key="di" class="mt-1">
              <InputGroup>
                <InputText v-model="row.domains[di + 1]"
                  :placeholder="t('hosts.domain_placeholder')" />
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
      <div class="flex gap-2">
        <Button icon="pi pi-check" :label="t('hosts.save')" size="small" @click="saveRawMode" />
        <Button icon="pi pi-times" :label="t('hosts.cancel')" severity="secondary" size="small" @click="cancelRawMode" />
      </div>
    </div>
  </div>
</template>
