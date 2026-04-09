<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { Card, InputText, Password, Button, AutoComplete } from 'primevue';
import { useRouter } from 'vue-router';
import { useToast } from 'primevue/usetoast';
import { I18nUtils } from 'easytier-frontend-lib';
import { getInitialApiHost, cleanAndLoadApiHosts, saveApiHost } from "../modules/api-host"
import { useI18n } from 'vue-i18n'
import ApiClient, { Credential, RegisterData } from '../modules/api';
import { setMustChangePasswordFlag } from '../modules/auth-status';
import { validatePasswordStrength } from '../modules/password-policy';

const { t } = useI18n()

defineProps<{
    isRegistering: boolean;
}>();

const api = computed<ApiClient>(() => new ApiClient(apiHost.value));
const router = useRouter();
const toast = useToast();

const username = ref('');
const password = ref('');
const registerUsername = ref('');
const registerPassword = ref('');
const registerConfirmPassword = ref('');
const captcha = ref('');
const captchaSrc = computed(() => api.value.captcha_url());
const registerPasswordValidation = computed(() => validatePasswordStrength(registerPassword.value));
const registerPasswordsMatch = computed(() => registerPassword.value === registerConfirmPassword.value);
const registerPasswordErrorMessage = computed(() => {
    if (registerPassword.value.length === 0 || registerPasswordValidation.value.valid) {
        return '';
    }

    return t(registerPasswordValidation.value.reasonKey!);
});
const registerConfirmPasswordErrorMessage = computed(() => {
    if (registerConfirmPassword.value.length === 0 || registerPasswordsMatch.value) {
        return '';
    }

    return t('web.common.password_mismatch');
});
const canRegister = computed(() => registerPasswordValidation.value.valid && registerPasswordsMatch.value);


const onSubmit = async () => {
    // Add your login logic here
    saveApiHost(apiHost.value);
    const credential: Credential = { username: username.value, password: password.value, };
    let ret = await api.value?.login(credential);
    if (ret.success) {
        localStorage.setItem('apiHost', btoa(apiHost.value));
        setMustChangePasswordFlag(Boolean(ret.mustChangePassword));
        router.push({
            name: 'dashboard',
            params: { apiHost: btoa(apiHost.value) },
        });
    } else {
        toast.add({ severity: 'error', summary: 'Login Failed', detail: ret.message, life: 2000 });
    }
};

const onRegister = async () => {
    if (!registerPasswordValidation.value.valid) {
        toast.add({
            severity: 'warn',
            summary: t('web.common.warning'),
            detail: t(registerPasswordValidation.value.reasonKey!),
            life: 3000,
        });
        return;
    }

    if (!registerPasswordsMatch.value) {
        toast.add({
            severity: 'warn',
            summary: t('web.common.warning'),
            detail: t('web.common.password_mismatch'),
            life: 3000,
        });
        return;
    }

    saveApiHost(apiHost.value);
    const credential: Credential = { username: registerUsername.value, password: registerPassword.value };
    const registerReq: RegisterData = { credentials: credential, captcha: captcha.value };
    let ret = await api.value?.register(registerReq);
    if (ret.success) {
        toast.add({ severity: 'success', summary: 'Register Success', detail: ret.message, life: 2000 });
        router.push({ name: 'login' });
    } else {
        toast.add({ severity: 'error', summary: 'Register Failed', detail: ret.message, life: 2000 });
    }
};

const apiHost = ref<string>(getInitialApiHost())
const apiHostSuggestions = ref<Array<string>>([])
const apiHostSearch = async (event: { query: string }) => {
    apiHostSuggestions.value = [];
    let hosts = cleanAndLoadApiHosts();
    if (event.query) {
        apiHostSuggestions.value.push(event.query);
    }
    hosts.forEach((host) => {
        apiHostSuggestions.value.push(host.value);
    });
}

const oidcEnabled = ref(false);
const lastCheckedHost = ref('');
const oidcCheckTimer = ref<ReturnType<typeof setTimeout> | null>(null);
const checkOidcConfig = () => {
    if (oidcCheckTimer.value) clearTimeout(oidcCheckTimer.value);
    oidcCheckTimer.value = setTimeout(async () => {
        const host = apiHost.value;
        if (host === lastCheckedHost.value) return;

        const enabled = (await new ApiClient(host).getOidcConfig()).enabled;
        // If host changes while request is in-flight, do not overwrite UI state.
        if (apiHost.value !== host) return;

        lastCheckedHost.value = host;
        oidcEnabled.value = enabled;
    }, 300);
};

watch(apiHost, () => {
    checkOidcConfig();
});

const onSsoLogin = () => {
    saveApiHost(apiHost.value);
    localStorage.setItem('apiHost', btoa(apiHost.value));
    window.location.href = api.value.oidcLoginUrl();
};

onMounted(() => {
    checkOidcConfig();
});

onBeforeUnmount(() => {
    if (oidcCheckTimer.value) {
        clearTimeout(oidcCheckTimer.value);
        oidcCheckTimer.value = null;
    }
});

</script>

<template>
    <div class="flex items-center justify-center min-h-screen">
        <Card class="w-full max-w-md p-6">
            <template #header>
                <h2 class="text-2xl font-semibold text-center">{{ isRegistering ? t('web.login.register') :
                    t('web.login.login') }}
                </h2>
            </template>
            <template #content>
                <div class="p-field mb-4">
                    <label for="api-host" class="block text-sm font-medium">{{ t('web.login.api_host') }}</label>
                    <AutoComplete id="api-host" v-model="apiHost" dropdown :suggestions="apiHostSuggestions"
                        @complete="apiHostSearch" class="w-full" />
                </div>
                <form v-if="!isRegistering" @submit.prevent="onSubmit" class="space-y-4">
                    <div class="p-field">
                        <label for="username" class="block text-sm font-medium">{{ t('web.login.username') }}</label>
                        <InputText id="username" v-model="username" required class="w-full" />
                    </div>
                    <div class="p-field">
                        <label for="password" class="block text-sm font-medium">{{ t('web.login.password') }}</label>
                        <Password id="password" v-model="password" required toggleMask :feedback="false" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.login')" type="submit" class="w-full" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.register')" type="button" class="w-full"
                            @click="saveApiHost(apiHost); $router.replace({ name: 'register' })" severity="secondary" />
                    </div>
                    <div v-if="oidcEnabled" class="flex items-center justify-between">
                        <Button :label="t('web.login.sso_login')" type="button" class="w-full" severity="info"
                            @click="onSsoLogin" />
                    </div>
                </form>

                <form v-else @submit.prevent="onRegister" class="space-y-4">
                    <div class="p-field">
                        <label for="register-username" class="block text-sm font-medium">{{ t('web.login.username')
                            }}</label>
                        <InputText id="register-username" v-model="registerUsername" required class="w-full" />
                    </div>
                    <div class="p-field">
                        <label for="register-password" class="block text-sm font-medium">{{ t('web.login.password')
                            }}</label>
                        <Password id="register-password" v-model="registerPassword" required toggleMask
                            :feedback="false" class="w-full" />
                        <small class="text-surface-500 dark:text-surface-400">
                            {{ t('web.common.password_strength_hint') }}
                        </small>
                        <small v-if="registerPasswordErrorMessage" class="block text-red-500 dark:text-red-400">
                            {{ registerPasswordErrorMessage }}
                        </small>
                    </div>
                    <div class="p-field">
                        <label for="register-confirm-password" class="block text-sm font-medium">
                            {{ t('web.settings.confirm_password') }}
                        </label>
                        <Password id="register-confirm-password" v-model="registerConfirmPassword" required toggleMask
                            :feedback="false" class="w-full" />
                        <small v-if="registerConfirmPasswordErrorMessage"
                            class="block text-red-500 dark:text-red-400">
                            {{ registerConfirmPasswordErrorMessage }}
                        </small>
                    </div>
                    <div class="p-field">
                        <label for="captcha" class="block text-sm font-medium">{{ t('web.login.captcha') }}</label>
                        <InputText id="captcha" v-model="captcha" required class="w-full" />
                        <img :src="captchaSrc" alt="Captcha" class="mt-2 mb-2" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.register')" type="submit" class="w-full"
                            :disabled="!canRegister" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.back_to_login')" type="button" class="w-full"
                            @click="saveApiHost(apiHost); $router.replace({ name: 'login' })" severity="secondary" />
                    </div>
                </form>

                <Button icon="pi pi-language" type="button" class="rounded-full absolute top-4 right-4 z-10"
                    style="box-shadow: 0 2px 8px rgba(0,0,0,0.08);" severity="contrast"
                    @click="I18nUtils.toggleLanguage" :aria-label="t('web.main.language')"
                    :v-tooltip="t('web.main.language')" />

            </template>


        </Card>
    </div>
</template>

<style scoped></style>
