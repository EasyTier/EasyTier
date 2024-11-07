<template>
    <div class="flex items-center justify-center min-h-screen">
        <Card class="w-full max-w-md p-6">
            <template #header>
                <h2 class="text-2xl font-semibold text-center">{{ isRegistering ? 'Register' : 'Login' }}
                </h2>
            </template>
            <template #content>
                <form v-if="!isRegistering" @submit.prevent="onSubmit" class="space-y-4">
                    <div class="p-field">
                        <label for="username" class="block text-sm font-medium">Username</label>
                        <InputText id="username" v-model="username" required class="w-full" />
                    </div>
                    <div class="p-field">
                        <label for="password" class="block text-sm font-medium">Password</label>
                        <Password id="password" v-model="password" required toggleMask />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button label="Login" type="submit" class="w-full" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button label="Register" type="button" class="w-full" @click="isRegistering = true"
                            severity="secondary" />
                    </div>
                </form>

                <form v-else @submit.prevent="onRegister" class="space-y-4">
                    <div class="p-field">
                        <label for="register-username" class="block text-sm font-medium">Username</label>
                        <InputText id="register-username" v-model="registerUsername" required class="w-full" />
                    </div>
                    <div class="p-field">
                        <label for="register-password" class="block text-sm font-medium">Password</label>
                        <Password id="register-password" v-model="registerPassword" required toggleMask
                            class="w-full" />
                    </div>
                    <div class="p-field">
                        <label for="captcha" class="block text-sm font-medium">Captcha</label>
                        <InputText id="captcha" v-model="captcha" required class="w-full" />
                        <img :src="captchaSrc" alt="Captcha" class="mt-2 mb-2" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button label="Register" type="submit" class="w-full" />
                    </div>
                    <div class="flex items-center justify-between">
                        <Button label="Back to Login" type="button" class="w-full" @click="isRegistering = false"
                            severity="secondary" />
                    </div>
                </form>
            </template>
        </Card>
    </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { Card, InputText, Password, Button } from 'primevue';
import ApiClient from '../modules/api';
import { Credential } from '../modules/api';

const props = defineProps({
    api: ApiClient,
});

const api = props.api;

const username = ref('');
const password = ref('');
const registerUsername = ref('');
const registerPassword = ref('');
const captcha = ref('');
const captchaSrc = computed(() => api?.captcha_url());
const isRegistering = ref(false);


const onSubmit = async () => {
    console.log('Username:', username.value);
    console.log('Password:', password.value);
    // Add your login logic here
    const credential: Credential = { username: username.value, password: password.value, };
    const ret = await api?.login(credential);
    alert(ret?.message);
};

const onRegister = () => {
    console.log('Register Username:', registerUsername.value);
    console.log('Register Password:', registerPassword.value);
    console.log('Captcha:', captcha.value);
    // Add your register logic here
};
</script>

<style scoped></style>
