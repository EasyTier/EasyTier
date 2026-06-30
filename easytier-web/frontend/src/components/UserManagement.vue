<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { Button, Card, DataTable, Column, InputSwitch, useToast, ConfirmDialog } from 'primevue';
import { useConfirm } from 'primevue/useconfirm';
import { useI18n } from 'vue-i18n'
import ApiClient from '../modules/api';

const { t } = useI18n()

const props = defineProps({
    api: ApiClient,
});

const toast = useToast();
const confirm = useConfirm();

interface UserInfo {
    id: number;
    username: string;
}

const users = ref<UserInfo[]>([]);
const registrationEnabled = ref(false);
const loadingUsers = ref(false);
const loadingRegistration = ref(false);

const loadUsers = async () => {
    loadingUsers.value = true;
    try {
        users.value = await props.api.admin_list_users();
    } catch (e: any) {
        if (e?.response?.status === 403) {
            toast.add({ severity: 'error', summary: 'Admin Only', detail: 'Only admin users can access this page', life: 3000 });
        } else {
            toast.add({ severity: 'error', summary: 'Failed to load users', detail: String(e), life: 3000 });
        }
        console.error(e);
    } finally {
        loadingUsers.value = false;
    }
};

const loadRegistrationStatus = async () => {
    loadingRegistration.value = true;
    try {
        registrationEnabled.value = await props.api.admin_get_registration_status();
    } catch (e) {
        console.error(e);
    } finally {
        loadingRegistration.value = false;
    }
};

const toggleRegistration = async (enabled: boolean) => {
    try {
        await props.api.admin_toggle_registration(enabled);
        registrationEnabled.value = enabled;
        toast.add({ severity: 'success', summary: 'Updated', detail: enabled ? 'Registration enabled' : 'Registration disabled', life: 2000 });
    } catch (e: any) {
        toast.add({ severity: 'error', summary: 'Failed', detail: String(e), life: 3000 });
    }
};

const confirmDeleteUser = (user: UserInfo) => {
    confirm.require({
        message: `Are you sure you want to delete user "${user.username}"?`,
        header: 'Delete User',
        icon: 'pi pi-exclamation-triangle',
        acceptClass: 'p-button-danger',
        accept: async () => {
            try {
                await props.api.admin_delete_user(user.id);
                toast.add({ severity: 'success', summary: 'Deleted', detail: `User "${user.username}" deleted`, life: 2000 });
                await loadUsers();
            } catch (e: any) {
                toast.add({ severity: 'error', summary: 'Failed', detail: String(e?.response?.data?.message || e), life: 3000 });
            }
        }
    });
};

onMounted(async () => {
    await Promise.all([loadUsers(), loadRegistrationStatus()]);
});

</script>

<template>
    <div class="space-y-6">
        <Card>
            <template #title>
                <div class="flex items-center gap-2">
                    <i class="pi pi-users"></i>
                    <span>User Management</span>
                </div>
            </template>
            <template #content>
                <div class="mb-6 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div class="flex items-center justify-between">
                        <div>
                            <h3 class="text-lg font-medium">{{ t('web.admin.registration_toggle') }}</h3>
                            <p class="text-sm text-gray-500 dark:text-gray-400">
                                {{ registrationEnabled ? t('web.admin.registration_enabled') : t('web.admin.registration_disabled') }}
                            </p>
                        </div>
                        <InputSwitch 
                            v-model="registrationEnabled" 
                            @update:model-value="toggleRegistration"
                            :disabled="loadingRegistration" 
                        />
                    </div>
                </div>

                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-medium">{{ t('web.admin.user_list') }} ({{ users.length }})</h3>
                    <Button icon="pi pi-refresh" severity="secondary" @click="loadUsers" :loading="loadingUsers" />
                </div>

                <DataTable :value="users" stripedRows responsiveLayout="scroll" :loading="loadingUsers">
                    <Column field="id" header="ID" :sortable="true" style="width: 80px" />
                    <Column field="username" :header="t('web.login.username')" :sortable="true" />
                    <Column header="Actions" style="width: 120px">
                        <template #body="{ data }">
                            <Button 
                                icon="pi pi-trash" 
                                severity="danger" 
                                variant="text"
                                :disabled="data.username === 'admin'"
                                @click="confirmDeleteUser(data)"
                                :tooltip="data.username === 'admin' ? 'Cannot delete admin' : 'Delete user'"
                            />
                        </template>
                    </Column>
                </DataTable>
            </template>
        </Card>
    </div>
    <ConfirmDialog />
</template>