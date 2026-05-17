<script setup lang="ts">
import { Button, Menu, Tab, TabList, TabPanel, TabPanels, Tabs } from 'primevue'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Acl, AclAction, AclChainType } from '../../types/network'
import AclChainEditor from './AclChainEditor.vue'
import AclGroupEditor from './AclGroupEditor.vue'

const acl = defineModel<Acl>({ required: true })

const { t } = useI18n()

const activeTab = ref(0)
const menu = ref()

const addMenuModel = ref([
  { label: () => t('acl.inbound'), command: () => addChain(AclChainType.Inbound) },
  { label: () => t('acl.outbound'), command: () => addChain(AclChainType.Outbound) },
  { label: () => t('acl.forward'), command: () => addChain(AclChainType.Forward) },
])

function addChain(type: AclChainType) {
  if (!acl.value.acl_v1) {
    acl.value.acl_v1 = { chains: [], group: { declares: [], members: [] } }
  }

  let defaultName = ''
  switch (type) {
    case AclChainType.Inbound: defaultName = 'Inbound'; break;
    case AclChainType.Outbound: defaultName = 'Outbound'; break;
    case AclChainType.Forward: defaultName = 'Forward'; break;
  }

  acl.value.acl_v1.chains.push({
    name: defaultName,
    chain_type: type,
    description: '',
    enabled: true,
    rules: [],
    default_action: AclAction.Allow
  })

  activeTab.value = acl.value.acl_v1.chains.length - 1
}

function removeChain(index: number) {
  if (confirm(t('acl.delete_chain_confirm'))) {
    acl.value.acl_v1?.chains.splice(index, 1)
    if (activeTab.value >= (acl.value.acl_v1?.chains.length || 0)) {
      activeTab.value = Math.max(0, (acl.value.acl_v1?.chains.length || 0))
    }
  }
}

function handleRenameGroup({ oldName, newName }: { oldName: string, newName: string }) {
  if (!acl.value.acl_v1) return
  acl.value.acl_v1.chains.forEach(chain => {
    chain.rules.forEach(rule => {
      rule.source_groups = rule.source_groups.map(g => g === oldName ? newName : g)
      rule.destination_groups = rule.destination_groups.map(g => g === oldName ? newName : g)
    })
  })
}

const groupNames = computed(() => {
  return acl.value.acl_v1?.group?.declares.map(g => g.group_name) || []
})

const tabs = computed(() => {
  const chains = acl.value.acl_v1?.chains || []
  const result: { type: string, label: string, index: number }[] = []

  if (chains.length === 0) {
    result.push({ type: 'empty', label: t('acl.chains'), index: 0 })
  }
  else {
    chains.forEach((c, index) => {
      result.push({
        type: 'chain',
        label: c.name || `Chain ${index}`,
        index
      })
    })
  }

  result.push({ type: 'groups', label: t('acl.groups'), index: result.length })
  return result
})
</script>

<template>
  <div class="flex flex-col gap-4">
    <Tabs v-model:value="activeTab">
      <div class="flex items-center border-b border-surface-200 dark:border-surface-700">
        <TabList class="flex-grow min-w-0 overflow-x-auto" style="border-bottom: none;">
          <Tab v-for="tab in tabs" :key="tab.type + tab.index" :value="tab.index">
            <div class="flex items-center gap-2 whitespace-nowrap">
              {{ tab.label }}
              <Button v-if="tab.type === 'chain'" icon="pi pi-times" severity="danger" text rounded size="small"
                class="w-6 h-6 p-0" @click.stop="removeChain(tab.index)" />
            </div>
          </Tab>
        </TabList>
        <div
          class="flex-shrink-0 flex items-center px-2 bg-white dark:bg-gray-900 border-l border-surface-100 dark:border-surface-800">
          <Button icon="pi pi-plus" text rounded size="small" class="w-8 h-8 p-0"
            @click="(event) => menu.toggle(event)" />
          <Menu ref="menu" :model="addMenuModel" :popup="true" />
        </div>
      </div>
      <TabPanels>
        <TabPanel v-for="tab in tabs" :key="'panel' + tab.type + tab.index" :value="tab.index">
          <!-- Empty State within TabPanel -->
          <div v-if="tab.type === 'empty'"
            class="py-8 flex flex-col items-center justify-center border-2 border-dashed border-surface-200 rounded-lg bg-surface-50 dark:bg-surface-900 dark:border-surface-700">
            <i class="pi pi-shield text-5xl mb-4 text-primary" />
            <div class="text-xl font-bold mb-2">{{ t('acl.chains') }}</div>
            <p class="text-surface-500 mb-8 text-center max-w-sm px-4">{{ t('acl.help') }}</p>
            <div class="flex flex-wrap gap-3 justify-center">
              <Button :label="t('acl.inbound')" icon="pi pi-arrow-down-left" @click="addChain(AclChainType.Inbound)" />
              <Button :label="t('acl.outbound')" icon="pi pi-arrow-up-right" @click="addChain(AclChainType.Outbound)" />
              <Button :label="t('acl.forward')" icon="pi pi-directions" @click="addChain(AclChainType.Forward)" />
            </div>
          </div>

          <!-- Rule Chains -->
          <div v-if="tab.type === 'chain' && acl.acl_v1 && acl.acl_v1.chains[tab.index]" class="py-4">
            <AclChainEditor v-model="acl.acl_v1.chains[tab.index]" :group-names="groupNames" />
          </div>

          <!-- Group Management -->
          <div v-if="tab.type === 'groups'" class="py-4">
            <template v-if="acl.acl_v1">
              <AclGroupEditor v-if="acl.acl_v1.group" v-model="acl.acl_v1.group" :group-names="groupNames"
                @rename-group="handleRenameGroup" />
              <div v-else class="flex justify-center p-4">
                <Button :label="t('web.common.add') + ' ' + t('acl.groups')"
                  @click="acl.acl_v1.group = { declares: [], members: [] }" />
              </div>
            </template>
            <div v-else class="flex justify-center p-4">
              <Button :label="t('acl.enabled')"
                @click="acl.acl_v1 = { chains: [], group: { declares: [], members: [] } }" />
            </div>
          </div>
        </TabPanel>
      </TabPanels>
    </Tabs>
  </div>
</template>
