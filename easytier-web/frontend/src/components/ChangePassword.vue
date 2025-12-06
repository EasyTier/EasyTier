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
    <div id="change-password-wrapper" class="flex items-center justify-center">
        <Card id="change-password-card" class="w-full max-w-md p-6">
            <template #header>
                <h2 id="change-password-title" class="text-2xl font-semibold text-center">Change Password
                </h2>
            </template>
            <template #content>
                <div id="change-password-body" class="flex flex-col space-y-4">
                    <Password id="change-password-input" v-model="password" placeholder="New Password" :feedback="false" toggleMask />
                    <Button id="change-password-submit" @click="changePassword" label="Ok" />
                </div>
            </template>
        </Card>
    </div>
</template>
