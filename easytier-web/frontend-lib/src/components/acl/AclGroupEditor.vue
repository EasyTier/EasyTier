<script setup lang="ts">
import { Button, Column, DataTable, Dialog, InputText, MultiSelect, Password } from 'primevue';
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { GroupIdentity, GroupInfo } from '../../types/network';

const props = defineProps<{
  groupNames?: string[]
}>()

const group = defineModel<GroupInfo>({ required: true })
const emit = defineEmits(['rename-group'])

const { t } = useI18n()

const editingGroup = ref<GroupIdentity | null>(null)
const editingGroupIndex = ref(-1)
const showGroupDialog = ref(false)
const oldGroupName = ref('')

function addGroup() {
  editingGroupIndex.value = -1
  editingGroup.value = {
    group_name: '',
    group_secret: '',
  }
  oldGroupName.value = ''
  showGroupDialog.value = true
}

function editGroup(index: number) {
  editingGroupIndex.value = index
  editingGroup.value = JSON.parse(JSON.stringify(group.value.declares[index]))
  oldGroupName.value = editingGroup.value?.group_name || ''
  showGroupDialog.value = true
}

function deleteGroup(index: number) {
  group.value.declares.splice(index, 1)
}

function saveGroup() {
  if (!editingGroup.value) return
  const newName = editingGroup.value.group_name

  if (editingGroupIndex.value === -1) {
    group.value.declares.push(editingGroup.value)
  } else {
    if (oldGroupName.value && oldGroupName.value !== newName) {
      // Sync in members
      group.value.members = group.value.members.map(m => m === oldGroupName.value ? newName : m)
      // Notify parent to sync in rules
      emit('rename-group', { oldName: oldGroupName.value, newName })
    }
    group.value.declares[editingGroupIndex.value] = editingGroup.value
  }
  showGroupDialog.value = false
}

</script>

<template>
  <div class="flex flex-col gap-6">
    <div class="flex flex-col gap-2">
      <div class="flex justify-between items-center">
        <div class="flex flex-col">
          <label class="font-bold text-lg">{{ t('acl.group.declares') }}</label>
          <small class="text-gray-500">{{ t('acl.group.help') }}</small>
        </div>
        <Button icon="pi pi-plus" :label="t('web.common.add')" severity="success" @click="addGroup" />
      </div>

      <DataTable :value="group.declares" responsiveLayout="scroll">
        <Column field="group_name" :header="t('acl.group.name')" />
        <Column field="group_secret" :header="t('acl.group.secret')">
          <template #body="{ data }">
            <Password v-model="data.group_secret" :feedback="false" toggleMask readonly plain class="w-full" />
          </template>
        </Column>
        <Column :header="t('web.common.edit')" headerStyle="width: 8rem">
          <template #body="{ index }">
            <div class="flex gap-2">
              <Button icon="pi pi-pencil" text rounded @click="editGroup(index)" />
              <Button icon="pi pi-trash" severity="danger" text rounded @click="deleteGroup(index)" />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <div class="flex flex-col gap-2">
      <label class="font-bold text-lg">{{ t('acl.group.members') }}</label>
      <MultiSelect v-model="group.members" :options="props.groupNames" multiple fluid filter
        :placeholder="t('acl.group.members')" />
    </div>

    <!-- Group Identity Dialog -->
    <Dialog v-model:visible="showGroupDialog" modal :header="t('acl.groups')" :style="{ width: '400px' }">
      <div v-if="editingGroup" class="flex flex-col gap-4 pt-2">
        <div class="flex flex-col gap-2">
          <label class="font-bold">{{ t('acl.group.name') }}</label>
          <InputText v-model="editingGroup.group_name" fluid />
        </div>
        <div class="flex flex-col gap-2">
          <label class="font-bold">{{ t('acl.group.secret') }}</label>
          <Password v-model="editingGroup.group_secret" :feedback="false" toggleMask fluid />
        </div>
      </div>
      <template #footer>
        <Button :label="t('web.common.cancel')" icon="pi pi-times" @click="showGroupDialog = false" text />
        <Button :label="t('web.common.save')" icon="pi pi-save" @click="saveGroup" />
      </template>
    </Dialog>
  </div>
</template>
