<script setup lang="ts">
import { AutoComplete, Button, Checkbox, Column, DataTable, Dialog, InputNumber, InputText, MultiSelect, ToggleButton } from 'primevue'
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouteDistanceConfig, RouteDistanceRule } from '../../types/network'

const props = defineProps<{
  groupNames?: string[]
}>()

const routeDistance = defineModel<RouteDistanceConfig>({ required: true })

const { t } = useI18n()

watch(() => routeDistance.value.rules, (newRules) => {
  if (!newRules) return
  const isSorted = newRules.every((rule, i) => i === 0 || (rule.priority || 0) <= (newRules[i - 1].priority || 0))
  if (!isSorted) {
    routeDistance.value.rules.sort((a, b) => (b.priority || 0) - (a.priority || 0))
  }
}, { deep: true, immediate: true })

const editingRule = ref<RouteDistanceRule | null>(null)
const editingRuleIndex = ref(-1)
const showRuleDialog = ref(false)
const genericSuggestions = ref<string[]>([])

function addRule() {
  editingRuleIndex.value = -1
  editingRule.value = {
    name: '',
    priority: routeDistance.value.rules.length,
    enabled: true,
    distance: routeDistance.value.default_distance || 1,
    destination_ips: [],
    destination_groups: [],
  }
  showRuleDialog.value = true
}

function editRule(index: number) {
  editingRuleIndex.value = index
  editingRule.value = JSON.parse(JSON.stringify(routeDistance.value.rules[index]))
  showRuleDialog.value = true
}

function deleteRule(index: number) {
  routeDistance.value.rules.splice(index, 1)
}

function saveRule() {
  if (!editingRule.value) return
  if (editingRuleIndex.value === -1) {
    routeDistance.value.rules.push(editingRule.value)
  } else {
    routeDistance.value.rules[editingRuleIndex.value] = editingRule.value
  }
  routeDistance.value.rules.sort((a, b) => (b.priority || 0) - (a.priority || 0))
  showRuleDialog.value = false
}

function onRowReorder(event: any) {
  routeDistance.value.rules = event.value
  routeDistance.value.rules.forEach((rule, index) => {
    rule.priority = routeDistance.value.rules.length - index - 1
  })
}
</script>

<template>
  <div class="flex flex-col gap-6">
    <div
      class="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 bg-gray-50 rounded-lg border border-gray-200 dark:bg-gray-900 dark:border-gray-700">
      <div class="flex flex-col gap-2">
        <label class="font-bold text-sm">{{ t('acl.route_distance.default_distance') }}</label>
        <InputNumber v-model="routeDistance.default_distance" :min="1" :max="2147483647" fluid />
      </div>
      <div class="flex items-center text-sm text-surface-500 pt-6 md:pt-0">
        {{ t('acl.route_distance.help') }}
      </div>
    </div>

    <div class="flex flex-row items-center gap-4 justify-between">
      <h4 class="text-md font-bold">{{ t('acl.route_distance.title') }}</h4>
      <Button icon="pi pi-plus" :label="t('acl.route_distance.add_rule')" severity="success" size="small" @click="addRule" />
    </div>

    <DataTable :value="routeDistance.rules" @row-reorder="onRowReorder" responsiveLayout="scroll">
      <Column rowReorder headerStyle="width: 3rem" />
      <Column field="enabled" :header="t('acl.rule.enabled')">
        <template #body="{ data }">
          <i class="pi" :class="data.enabled ? 'pi-check-circle text-green-500' : 'pi-times-circle text-red-500'"></i>
        </template>
      </Column>
      <Column field="name" :header="t('acl.rule.name')" />
      <Column field="distance" :header="t('acl.route_distance.distance')" />
      <Column :header="t('acl.match')">
        <template #body="{ data }">
          <div class="flex flex-col gap-2 py-1">
            <div class="flex flex-wrap gap-1 items-center overflow-hidden">
              <span v-for="ip in data.destination_ips" :key="ip"
                class="font-mono text-xs bg-surface-100 dark:bg-surface-800 px-1.5 py-0.5 rounded">{{ ip }}</span>
              <span v-for="grp in data.destination_groups" :key="grp"
                class="text-xs font-bold text-purple-600 dark:text-purple-400">@{{ grp }}</span>
              <span v-if="data.foreign_node === true" class="text-xs font-bold text-amber-600 dark:text-amber-400">
                {{ t('acl.route_distance.foreign_node') }}
              </span>
              <span v-if="!data.destination_ips.length && !data.destination_groups.length && data.foreign_node !== true"
                class="text-gray-400">*</span>
            </div>
          </div>
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

    <Dialog v-model:visible="showRuleDialog" modal :header="t('acl.route_distance.edit_rule')"
      :style="{ width: '90vw', maxWidth: '600px' }">
      <div v-if="editingRule" class="flex flex-col gap-4">
        <div class="flex flex-row gap-4 items-center">
          <div class="flex flex-col gap-2 grow">
            <label class="font-bold">{{ t('acl.rule.name') }}</label>
            <InputText v-model="editingRule.name" fluid />
          </div>
          <div class="flex flex-col gap-2">
            <label class="font-bold">{{ t('acl.rule.enabled') }}</label>
            <ToggleButton v-model="editingRule.enabled" on-icon="pi pi-check" off-icon="pi pi-times"
              :on-label="t('web.common.enable')" :off-label="t('web.common.disable')" class="w-24" />
          </div>
        </div>

        <div class="flex flex-row gap-4 flex-wrap">
          <div class="flex flex-col gap-2 grow">
            <label class="font-bold">{{ t('acl.route_distance.priority') }}</label>
            <InputNumber v-model="editingRule.priority" :min="0" :max="65535" fluid />
          </div>
          <div class="flex flex-col gap-2 grow">
            <label class="font-bold">{{ t('acl.route_distance.distance') }}</label>
            <InputNumber v-model="editingRule.distance" :min="1" :max="2147483647" fluid />
          </div>
        </div>

        <div class="flex flex-col gap-2">
          <label class="font-bold">{{ t('acl.route_distance.dst_ips') }}</label>
          <AutoComplete v-model="editingRule.destination_ips" multiple fluid :suggestions="genericSuggestions"
            @complete="genericSuggestions = [$event.query]" :placeholder="t('chips_placeholder', ['10.126.126.0/24'])" />
        </div>

        <div class="flex flex-col gap-2">
          <label class="font-bold">{{ t('acl.route_distance.dst_groups') }}</label>
          <MultiSelect v-model="editingRule.destination_groups" :options="props.groupNames" multiple fluid filter
            :placeholder="t('acl.route_distance.dst_groups')" />
        </div>

        <div class="flex items-center gap-2">
          <Checkbox v-model="editingRule.foreign_node" :binary="true" inputId="route-distance-foreign-node" />
          <label for="route-distance-foreign-node" class="font-bold">{{ t('acl.route_distance.foreign_node') }}</label>
          <small class="text-surface-500">{{ t('acl.route_distance.foreign_node_hint') }}</small>
        </div>
      </div>

      <template #footer>
        <Button :label="t('web.common.cancel')" icon="pi pi-times" @click="showRuleDialog = false" text />
        <Button :label="t('web.common.save')" icon="pi pi-save" @click="saveRule" />
      </template>
    </Dialog>
  </div>
</template>
