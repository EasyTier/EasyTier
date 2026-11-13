<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Card, InputText, Password, Button } from 'primevue';
import { useRouter } from 'vue-router';
import { useToast } from 'primevue/usetoast';
import { I18nUtils } from 'easytier-frontend-lib';
import { getApiBase } from "../modules/api-host"
import { useI18n } from 'vue-i18n'
import ApiClient, { Credential, RegisterData } from '../modules/api';

const { t } = useI18n()

defineProps<{
    isRegistering: boolean;
}>();

const api = computed<ApiClient>(() => new ApiClient(getApiBase()));
const router = useRouter();
const toast = useToast();

const username = ref('');
const password = ref('');
const registerUsername = ref('');
const registerPassword = ref('');
const captcha = ref('');
const captchaSrc = computed(() => api.value.captcha_url());

const onSubmit = async () => {
    // Add your login logic here
    const credential: Credential = { username: username.value, password: password.value, };
    let ret = await api.value?.login(credential);
    if (ret.success) {
        router.push({ name: 'dashboard' });
    } else {
        toast.add({ severity: 'error', summary: 'Login Failed', detail: ret.message, life: 2000 });
    }
};

const onRegister = async () => {
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

const oidcEnabled = ref(false);

const checkOidcConfig = async () => {
    oidcEnabled.value = (await api.value.getOidcConfig()).enabled;
};

const onSsoLogin = () => {
    window.location.href = api.value.oidcLoginUrl();
};

onMounted(async () => {
    await checkOidcConfig();
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
                            @click="$router.replace({ name: 'register' })" severity="secondary" />
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
                            :feedback="false" />
                    </div>
                    <div class="p-field">
                        <label for="captcha" class="block text-sm font-medium">{{ t('web.login.captcha') }}</label>
                        <InputText id="captcha" v-model="captcha" required class="w-full" />
                        <img :src="captchaSrc" alt="Captcha" class="mt-2 mb-2" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.register')" type="submit" class="w-full" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button :label="t('web.login.back_to_login')" type="button" class="w-full"
                            @click="$router.replace({ name: 'login' })" severity="secondary" />
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
