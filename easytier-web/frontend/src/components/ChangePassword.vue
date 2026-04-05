<script lang="ts" setup>
import { computed, inject, ref } from 'vue';
import { Card, Password, Button } from 'primevue';
import { useToast } from 'primevue/usetoast';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import ApiClient from '../modules/api';
import { clearMustChangePasswordFlag } from '../modules/auth-status';

const dialogRef = inject<any>('dialogRef');

const api = computed<ApiClient>(() => dialogRef.value.data.api);

const password = ref('');
const toast = useToast();
const router = useRouter();
const { t } = useI18n();
const passwordIsEmpty = computed(() => password.value.trim().length === 0);

const changePassword = async () => {
    if (passwordIsEmpty.value) {
        toast.add({
            severity: 'warn',
            summary: t('web.common.warning'),
            detail: t('web.settings.new_password_empty'),
            life: 3000,
        });
        return;
    }

    try {
        await api.value.change_password(password.value);
        toast.add({
            severity: 'success',
            summary: t('web.common.success'),
            detail: t('web.main.password_changed_relogin'),
            life: 3000,
        });
        clearMustChangePasswordFlag();
        dialogRef.value.close();
        router.push({ name: 'login' });
    } catch (error) {
        toast.add({
            severity: 'error',
            summary: t('web.common.error'),
            detail: error instanceof Error ? error.message : String(error),
            life: 3000,
        });
    }
}
</script>

<template>
    <div class="flex items-center justify-center">
        <Card class="w-full max-w-md p-6">
            <template #header>
                <h2 class="text-2xl font-semibold text-center">{{ t('web.main.change_password') }}
                </h2>
            </template>
            <template #content>
                <div class="flex flex-col space-y-4">
                    <Password v-model="password" :placeholder="t('web.settings.new_password')" :feedback="false"
                        toggleMask />
                    <Button @click="changePassword" :label="t('web.common.confirm')"
                        :disabled="passwordIsEmpty" />
                </div>
            </template>
        </Card>
    </div>
</template>
