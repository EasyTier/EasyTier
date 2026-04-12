<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { Card, InputText, Password, Button, AutoComplete } from 'primevue';
import { useRouter } from 'vue-router';
import { useToast } from 'primevue/usetoast';
import { I18nUtils } from 'easytier-frontend-lib';
import { getInitialApiHost, cleanAndLoadApiHosts, saveApiHost } from "../modules/api-host"
import { useI18n } from 'vue-i18n'
import ApiClient, { Credential, RegisterData, setToken } from '../modules/api';

const { t } = useI18n()

const props = defineProps<{
    isRegistering: boolean;
}>();

const api = computed<ApiClient>(() => new ApiClient(apiHost.value));
const router = useRouter();
const toast = useToast();

const username = ref('');
const password = ref('');
const registerUsername = ref('');
const registerPassword = ref('');
const captcha = ref('');
const captchaId = ref('');
const captchaSrc = ref('');
const captchaObjectUrl = ref<string | null>(null);
let captchaRequestSeq = 0;

const revokeCaptchaUrl = () => {
    if (captchaObjectUrl.value) {
        URL.revokeObjectURL(captchaObjectUrl.value);
        captchaObjectUrl.value = null;
    }
};

const resetCaptchaState = () => {
    captchaRequestSeq += 1;
    revokeCaptchaUrl();
    captchaSrc.value = '';
    captchaId.value = '';
    captcha.value = '';
};

const loadCaptcha = async () => {
    if (!props.isRegistering) {
        resetCaptchaState();
        return;
    }

    const requestSeq = ++captchaRequestSeq;
    captchaId.value = '';
    captcha.value = '';

    try {
        const response = await api.value.fetchCaptcha();
        if (requestSeq !== captchaRequestSeq) {
            return;
        }
        if (!response.captcha_id) {
            throw new Error('Missing captcha id header');
        }

        revokeCaptchaUrl();
        const objectUrl = URL.createObjectURL(response.blob);
        captchaObjectUrl.value = objectUrl;
        captchaSrc.value = objectUrl;
        captchaId.value = response.captcha_id;
    } catch (error) {
        if (requestSeq !== captchaRequestSeq) {
            return;
        }

        resetCaptchaState();
        toast.add({ severity: 'error', summary: 'Captcha Failed', detail: String(error), life: 2000 });
    }
};


const onSubmit = async () => {
    // Add your login logic here
    saveApiHost(apiHost.value);
    const credential: Credential = { username: username.value, password: password.value, };
    let ret = await api.value?.login(credential);
    if (ret.success) {
        localStorage.setItem('apiHost', btoa(apiHost.value));
        router.push({
            name: 'dashboard',
            params: { apiHost: btoa(apiHost.value) },
        });
    } else {
        toast.add({ severity: 'error', summary: 'Login Failed', detail: ret.message, life: 2000 });
    }
};

const onRegister = async () => {
    saveApiHost(apiHost.value);
    if (!captchaId.value) {
        await loadCaptcha();
        toast.add({ severity: 'error', summary: 'Register Failed', detail: 'Captcha unavailable, please retry.', life: 2000 });
        return;
    }

    const credential: Credential = { username: registerUsername.value, password: registerPassword.value };
    const registerReq: RegisterData = { credentials: credential, captcha_id: captchaId.value, captcha: captcha.value };
    let ret = await api.value?.register(registerReq);
    if (ret.success) {
        toast.add({ severity: 'success', summary: 'Register Success', detail: ret.message, life: 2000 });
        router.push({ name: 'login' });
    } else {
        toast.add({ severity: 'error', summary: 'Register Failed', detail: ret.message, life: 2000 });
        await loadCaptcha();
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
    if (props.isRegistering) {
        void loadCaptcha();
    }
});

watch(() => props.isRegistering, (isRegistering) => {
    if (isRegistering) {
        void loadCaptcha();
    } else {
        resetCaptchaState();
    }
});

const onSsoLogin = () => {
    saveApiHost(apiHost.value);
    localStorage.setItem('apiHost', btoa(apiHost.value));
    window.location.href = api.value.oidcLoginUrl();
};

const parseExpiresAt = (raw: string): string | null => {
    const numeric = Number(raw);
    if (Number.isFinite(numeric) && /^\d+$/.test(raw.trim())) {
        return new Date(numeric * 1000).toISOString();
    }

    const parsedMs = Date.parse(raw);
    if (Number.isNaN(parsedMs)) {
        return null;
    }

    return new Date(parsedMs).toISOString();
};

onMounted(() => {
    checkOidcConfig();
    if (props.isRegistering) {
        void loadCaptcha();
    }
    const query = router.currentRoute.value.query;
    const expiresAt = query.expires_at ? parseExpiresAt(query.expires_at as string) : null;
    if (query.token && expiresAt) {
        setToken(query.token as string, expiresAt);
        saveApiHost(apiHost.value);
        localStorage.setItem('apiHost', btoa(apiHost.value));
        router.replace({
            name: 'dashboard',
            params: { apiHost: btoa(apiHost.value) },
        });
    }
});

onBeforeUnmount(() => {
    resetCaptchaState();
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
                    </div>
                    <div class="p-field">
                        <label for="captcha" class="block text-sm font-medium">{{ t('web.login.captcha') }}</label>
                        <InputText id="captcha" v-model="captcha" required class="w-full" />
                        <img v-if="captchaSrc" :src="captchaSrc" alt="Captcha" class="mt-2 mb-2 cursor-pointer"
                            @click="loadCaptcha" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.register')" type="submit" class="w-full" />
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
