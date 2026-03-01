<script setup lang="ts">
import { Button, Column, DataTable, Divider, InputText, Select, SelectButton, ToggleButton } from 'primevue'
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { AclAction, AclChain, AclChainType, AclProtocol, AclRule } from '../../types/network'
import AclRuleDialog from './AclRuleDialog.vue'

const props = defineProps<{
  groupNames?: string[]
}>()

const chain = defineModel<AclChain>({ required: true })

const { t } = useI18n()

watch(() => chain.value.rules, (newRules) => {
  if (!newRules) return
  const isSorted = newRules.every((rule, i) => i === 0 || (rule.priority || 0) <= (newRules[i - 1].priority || 0))
  if (!isSorted) {
    chain.value.rules.sort((a, b) => (b.priority || 0) - (a.priority || 0))
  }
}, { deep: true, immediate: true })

const actionOptions = [
  { label: () => t('acl.allow'), value: AclAction.Allow },
  { label: () => t('acl.drop'), value: AclAction.Drop },
]

const chainTypeOptions = [
  { label: () => t('acl.inbound'), value: AclChainType.Inbound },
  { label: () => t('acl.outbound'), value: AclChainType.Outbound },
  { label: () => t('acl.forward'), value: AclChainType.Forward },
]

const editingRule = ref<AclRule | null>(null)
const editingRuleIndex = ref(-1)
const showRuleDialog = ref(false)

function getProtocolLabel(proto: AclProtocol) {
  switch (proto) {
    case AclProtocol.Any: return t('acl.any')
    case AclProtocol.TCP: return 'TCP'
    case AclProtocol.UDP: return 'UDP'
    case AclProtocol.ICMP: return 'ICMP'
    case AclProtocol.ICMPv6: return 'ICMPv6'
    default: return t('event.Unknown')
  }
}

function getActionLabel(action: AclAction) {
  switch (action) {
    case AclAction.Allow: return t('acl.allow')
    case AclAction.Drop: return t('acl.drop')
    default: return t('event.Unknown')
  }
}

function addRule() {
  editingRuleIndex.value = -1
  editingRule.value = {
    name: '',
    description: '',
    priority: chain.value.rules.length,
    enabled: true,
    protocol: AclProtocol.Any,
    ports: [],
    source_ips: [],
    destination_ips: [],
    source_ports: [],
    action: AclAction.Allow,
    rate_limit: 0,
    burst_limit: 0,
    stateful: false,
    source_groups: [],
    destination_groups: [],
  }
  showRuleDialog.value = true
}

function editRule(index: number) {
  editingRuleIndex.value = index
  editingRule.value = JSON.parse(JSON.stringify(chain.value.rules[index]))
  showRuleDialog.value = true
}

function deleteRule(index: number) {
  chain.value.rules.splice(index, 1)
}

function saveRule(rule: AclRule) {
  if (editingRuleIndex.value === -1) {
    chain.value.rules.push(rule)
  } else {
    chain.value.rules[editingRuleIndex.value] = rule
  }
  chain.value.rules.sort((a, b) => (b.priority || 0) - (a.priority || 0))
}

function onRowReorder(event: any) {
  chain.value.rules = event.value
  // Update priorities based on new order (higher priority at top)
  chain.value.rules.forEach((rule, index) => {
    rule.priority = chain.value.rules.length - index - 1
  })
}
</script>

<template>
  <div class="flex flex-col gap-6">
    <!-- Chain Metadata Section -->
    <div
      class="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg border border-gray-200 dark:bg-gray-900 dark:border-gray-700">
      <div class="flex flex-col gap-2">
        <label class="font-bold text-sm">{{ t('acl.chain.name') }}</label>
        <InputText v-model="chain.name" size="small" />
      </div>
      <div class="flex flex-col gap-2">
        <label class="font-bold text-sm">{{ t('acl.rule.description') }}</label>
        <InputText v-model="chain.description" size="small" />
      </div>

      <div class="flex items-center gap-6 col-span-full border-t pt-2 mt-2 dark:border-gray-700">
        <div class="flex items-center gap-2">
          <label class="font-bold text-sm">{{ t('acl.rule.enabled') }}</label>
          <ToggleButton v-model="chain.enabled" on-icon="pi pi-check" off-icon="pi pi-times"
            :on-label="t('web.common.enable')" :off-label="t('web.common.disable')" class="w-24" />
        </div>
        <div class="flex items-center gap-2">
          <label class="font-bold text-sm">{{ t('acl.chain.type') }}</label>
          <Select v-model="chain.chain_type" :options="chainTypeOptions" :option-label="opt => opt.label()"
            option-value="value" size="small" class="w-40" />
        </div>
        <div class="flex items-center gap-2 ml-auto">
          <label class="font-bold text-sm">{{ t('acl.default_action') }}</label>
          <SelectButton v-model="chain.default_action" :options="actionOptions" :option-label="opt => opt.label()"
            option-value="value" :allow-empty="false" />
        </div>
      </div>
    </div>

    <div class="flex flex-row items-center gap-4 justify-between">
      <h4 class="text-md font-bold">{{ t('acl.rules') }}</h4>
      <Button icon="pi pi-plus" :label="t('acl.add_rule')" severity="success" size="small" @click="addRule" />
    </div>

    <DataTable :value="chain.rules" @row-reorder="onRowReorder" responsiveLayout="scroll">
      <Column rowReorder headerStyle="width: 3rem" />
      <Column field="enabled" :header="t('acl.rule.enabled')">
        <template #body="{ data }">
          <i class="pi" :class="data.enabled ? 'pi-check-circle text-green-500' : 'pi-times-circle text-red-500'"></i>
        </template>
      </Column>
      <Column field="name" :header="t('acl.rule.name')" />
      <Column :header="t('acl.match')">
        <template #body="{ data }">
          <div class="flex flex-col gap-2 py-1">
            <div class="flex items-center gap-2">
              <span
                class="px-2 py-0.5 bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-md text-[10px] font-bold uppercase tracking-wider">
                {{ getProtocolLabel(data.protocol) }}
              </span>
            </div>

            <div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3">
              <div class="flex items-center gap-1.5 min-w-0">
                <span class="text-[10px] font-bold text-gray-400 uppercase w-7">Src</span>
                <div class="flex flex-wrap gap-1 items-center overflow-hidden">
                  <span v-for="ip in data.source_ips" :key="ip"
                    class="font-mono text-xs bg-surface-100 dark:bg-surface-800 px-1.5 py-0.5 rounded">{{ ip }}</span>
                  <span v-for="grp in data.source_groups" :key="grp"
                    class="text-xs font-bold text-purple-600 dark:text-purple-400">@{{ grp }}</span>
                  <span v-if="data.source_ports.length" class="text-xs text-blue-600 dark:text-blue-400 font-mono">:{{
                    data.source_ports.join(',') }}</span>
                  <span v-if="!data.source_ips.length && !data.source_groups.length" class="text-gray-400">*</span>
                </div>
              </div>

              <i class="pi pi-arrow-right hidden sm:block text-gray-300 text-xs"></i>
              <Divider layout="horizontal" class="sm:hidden my-1" />

              <div class="flex items-center gap-1.5 min-w-0">
                <span class="text-[10px] font-bold text-gray-400 uppercase w-7">Dst</span>
                <div class="flex flex-wrap gap-1 items-center overflow-hidden">
                  <span v-for="ip in data.destination_ips" :key="ip"
                    class="font-mono text-xs bg-surface-100 dark:bg-surface-800 px-1.5 py-0.5 rounded">{{ ip }}</span>
                  <span v-for="grp in data.destination_groups" :key="grp"
                    class="text-xs font-bold text-purple-600 dark:text-purple-400">@{{ grp }}</span>
                  <span v-if="data.ports.length" class="text-xs text-blue-600 dark:text-blue-400 font-mono">:{{
                    data.ports.join(',') }}</span>
                  <span v-if="!data.destination_ips.length && !data.destination_groups.length"
                    class="text-gray-400">*</span>
                </div>
              </div>
            </div>
          </div>
        </template>
      </Column>
      <Column field="action" :header="t('acl.rule.action')">
        <template #body="{ data }">
          <span :class="data.action === AclAction.Allow ? 'text-green-600' : 'text-red-600 font-bold'">
            {{ getActionLabel(data.action) }}
          </span>
        </template>
      </Column>
      <Column :header="t('web.common.edit')">
        <template #body="{ index }">
          <div class="flex gap-2">
            <Button icon="pi pi-pencil" text rounded @click="editRule(index)" />
            <Button icon="pi pi-trash" severity="danger" text rounded @click="deleteRule(index)" />
          </div>
        </template>
      </Column>
    </DataTable>

    <AclRuleDialog v-if="showRuleDialog && editingRule" v-model:visible="showRuleDialog" v-model:rule="editingRule"
      :group-names="props.groupNames" @save="saveRule" />
  </div>
</template>
