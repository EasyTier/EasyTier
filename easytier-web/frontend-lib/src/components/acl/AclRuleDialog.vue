<script setup lang="ts">
import { AutoComplete, Button, Checkbox, Dialog, InputNumber, InputText, MultiSelect, Panel, SelectButton, ToggleButton } from 'primevue';
import { computed, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { AclAction, AclProtocol, AclRule } from '../../types/network';

const props = defineProps<{
  visible: boolean
  groupNames?: string[]
}>()

const emit = defineEmits(['update:visible', 'save'])

const rule = defineModel<AclRule>('rule', { required: true })

const { t } = useI18n()

const protocolOptions = [
  { label: () => t('acl.any'), value: AclProtocol.Any },
  { label: 'TCP', value: AclProtocol.TCP },
  { label: 'UDP', value: AclProtocol.UDP },
  { label: 'ICMP', value: AclProtocol.ICMP },
  { label: 'ICMPv6', value: AclProtocol.ICMPv6 },
]

const actionOptions = [
  { label: () => t('acl.allow'), value: AclAction.Allow },
  { label: () => t('acl.drop'), value: AclAction.Drop },
]

const showPorts = computed(() => {
  return rule.value.protocol === AclProtocol.TCP || rule.value.protocol === AclProtocol.UDP || rule.value.protocol === AclProtocol.Any
})

function close() {
  emit('update:visible', false)
}

function save() {
  emit('save', rule.value)
  close()
}

// Suggestions for IP/Port AutoComplete
const genericSuggestions = ref<string[]>([])
</script>

<template>
  <Dialog :visible="visible" @update:visible="emit('update:visible', $event)" modal :header="t('acl.edit_rule')"
    :style="{ width: '90vw', maxWidth: '600px' }">
    <div class="flex flex-col gap-4">
      <div class="flex flex-row gap-4 items-center">
        <div class="flex flex-col gap-2 grow">
          <label class="font-bold">{{ t('acl.rule.name') }}</label>
          <InputText v-model="rule.name" fluid />
        </div>
        <div class="flex flex-col gap-2">
          <label class="font-bold">{{ t('acl.rule.enabled') }}</label>
          <ToggleButton v-model="rule.enabled" on-icon="pi pi-check" off-icon="pi pi-times"
            :on-label="t('web.common.enable')" :off-label="t('web.common.disable')" class="w-24" />
        </div>
      </div>

      <div class="flex flex-col gap-2">
        <label class="font-bold">{{ t('acl.rule.description') }}</label>
        <InputText v-model="rule.description" fluid />
      </div>

      <div class="flex flex-row gap-4 flex-wrap">
        <div class="flex flex-col gap-2 grow">
          <label class="font-bold">{{ t('acl.rule.action') }}</label>
          <SelectButton v-model="rule.action" :options="actionOptions" :option-label="opt => opt.label()"
            option-value="value" :allow-empty="false" />
        </div>
        <div class="flex flex-col gap-2 grow">
          <label class="font-bold">{{ t('acl.rule.protocol') }}</label>
          <SelectButton v-model="rule.protocol" :options="protocolOptions"
            :option-label="opt => typeof opt.label === 'function' ? opt.label() : opt.label" option-value="value"
            :allow-empty="false" />
        </div>
      </div>

      <Panel :header="t('acl.rules')" toggleable>
        <div class="flex flex-col gap-4">
          <div class="flex flex-col gap-2">
            <label class="font-bold">{{ t('acl.rule.src_ips') }}</label>
            <AutoComplete v-model="rule.source_ips" multiple fluid :suggestions="genericSuggestions"
              @complete="genericSuggestions = [$event.query]"
              :placeholder="t('chips_placeholder', ['10.126.126.0/24'])" />
          </div>
          <div class="flex flex-col gap-2">
            <label class="font-bold">{{ t('acl.rule.dst_ips') }}</label>
            <AutoComplete v-model="rule.destination_ips" multiple fluid :suggestions="genericSuggestions"
              @complete="genericSuggestions = [$event.query]"
              :placeholder="t('chips_placeholder', ['10.126.126.2/32'])" />
          </div>

          <div v-if="showPorts" class="flex flex-row gap-4 flex-wrap">
            <div class="flex flex-col gap-2 grow">
              <label class="font-bold">{{ t('acl.rule.src_ports') }}</label>
              <AutoComplete v-model="rule.source_ports" multiple fluid :suggestions="genericSuggestions"
                @complete="genericSuggestions = [$event.query]" placeholder="e.g. 80, 1000-2000" />
            </div>
            <div class="flex flex-col gap-2 grow">
              <label class="font-bold">{{ t('acl.rule.dst_ports') }}</label>
              <AutoComplete v-model="rule.ports" multiple fluid :suggestions="genericSuggestions"
                @complete="genericSuggestions = [$event.query]" placeholder="e.g. 80, 1000-2000" />
            </div>
          </div>
        </div>
      </Panel>

      <Panel :header="t('advanced_settings')" toggleable collapsed>
        <div class="flex flex-col gap-4">
          <div class="flex items-center gap-2">
            <Checkbox v-model="rule.stateful" :binary="true" inputId="rule-stateful" />
            <label for="rule-stateful" class="font-bold">{{ t('acl.rule.stateful') }}</label>
          </div>

          <div class="flex flex-row gap-4 flex-wrap">
            <div class="flex flex-col gap-2 grow">
              <label class="font-bold">{{ t('acl.rule.rate_limit') }}</label>
              <InputNumber v-model="rule.rate_limit" :min="0" placeholder="0 = no limit" fluid />
            </div>
            <div class="flex flex-col gap-2 grow">
              <label class="font-bold">{{ t('acl.rule.burst_limit') }}</label>
              <InputNumber v-model="rule.burst_limit" :min="0" placeholder="0 = no limit" fluid />
            </div>
          </div>

          <div class="flex flex-col gap-2">
            <label class="font-bold">{{ t('acl.rule.src_groups') }}</label>
            <MultiSelect v-model="rule.source_groups" :options="props.groupNames" multiple fluid filter
              :placeholder="t('acl.rule.src_groups')" />
          </div>
          <div class="flex flex-col gap-2">
            <label class="font-bold">{{ t('acl.rule.dst_groups') }}</label>
            <MultiSelect v-model="rule.destination_groups" :options="props.groupNames" multiple fluid filter
              :placeholder="t('acl.rule.dst_groups')" />
          </div>
        </div>
      </Panel>
    </div>

    <template #footer>
      <Button :label="t('web.common.cancel')" icon="pi pi-times" @click="close" text />
      <Button :label="t('web.common.save')" icon="pi pi-save" @click="save" />
    </template>
  </Dialog>
</template>
