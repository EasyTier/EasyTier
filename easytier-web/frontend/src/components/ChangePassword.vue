<script lang="ts" setup>
import { computed, inject, ref } from 'vue';
import { Card, Password, Button } from 'primevue';
import ApiClient from '../modules/api';

const dialogRef = inject<any>('dialogRef');

const api = computed<ApiClient>(() => dialogRef.value.data.api);

const password = ref('');

const changePassword = async () => {
    await api.value.change_password(password.value);
    dialogRef.value.close();
}
</script>

<template>
    <div class="flex items-center justify-center">
        <Card class="w-full max-w-md p-6">
            <template #header>
                <h2 class="text-2xl font-semibold text-center">Change Password
                </h2>
            </template>
            <template #content>
                <div class="flex flex-col space-y-4">
                    <Password v-model="password" placeholder="New Password" :feedback="false" toggleMask />
                    <Button @click="changePassword" label="Ok" />
                </div>
            </template>
        </Card>
    </div>
</template>