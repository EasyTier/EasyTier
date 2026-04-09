<script lang="ts" setup>
import { computed, inject, ref } from 'vue';
import { Card, Password, Button } from 'primevue';
import { useToast } from 'primevue/usetoast';
import { useRouter } from 'vue-router';
import { useI18n } from 'vue-i18n';
import ApiClient from '../modules/api';
import { clearMustChangePasswordFlag } from '../modules/auth-status';
import { validatePasswordStrength } from '../modules/password-policy';

const dialogRef = inject<any>('dialogRef');

const api = computed<ApiClient>(() => dialogRef.value.data.api);

const password = ref('');
const confirmPassword = ref('');
const toast = useToast();
const router = useRouter();
const { t } = useI18n();
const passwordValidation = computed(() => validatePasswordStrength(password.value));
const passwordMatches = computed(() => password.value === confirmPassword.value);
const passwordErrorMessage = computed(() => {
    if (password.value.length === 0 || passwordValidation.value.valid) {
        return '';
    }

    return t(passwordValidation.value.reasonKey!);
});
const confirmPasswordErrorMessage = computed(() => {
    if (confirmPassword.value.length === 0 || passwordMatches.value) {
        return '';
    }

    return t('web.common.password_mismatch');
});
const canSubmit = computed(() => passwordValidation.value.valid && passwordMatches.value);

const changePassword = async () => {
    if (!passwordValidation.value.valid) {
        toast.add({
            severity: 'warn',
            summary: t('web.common.warning'),
            detail: t(passwordValidation.value.reasonKey!),
            life: 3000,
        });
        return;
    }

    if (!passwordMatches.value) {
        toast.add({
            severity: 'warn',
            summary: t('web.common.warning'),
            detail: t('web.common.password_mismatch'),
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
                    <Password v-model="confirmPassword" :placeholder="t('web.settings.confirm_password')"
                        :feedback="false" toggleMask />
                    <small class="text-surface-500 dark:text-surface-400">
                        {{ t('web.common.password_strength_hint') }}
                    </small>
                    <small v-if="passwordErrorMessage" class="text-red-500 dark:text-red-400">
                        {{ passwordErrorMessage }}
                    </small>
                    <small v-if="confirmPasswordErrorMessage" class="text-red-500 dark:text-red-400">
                        {{ confirmPasswordErrorMessage }}
                    </small>
                    <Button @click="changePassword" :label="t('web.common.confirm')"
                        :disabled="!canSubmit" />
                </div>
            </template>
        </Card>
    </div>
</template>
