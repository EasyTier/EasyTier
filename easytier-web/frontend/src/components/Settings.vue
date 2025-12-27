<script setup lang="ts">
import { Button, Slider, Card, Select } from 'primevue';
import { ref } from 'vue';
import { useBackgroundSettings, fileToDataUrl } from '../modules/backgroundSettings';
import { useI18n } from 'vue-i18n';
import { useThemeSettings, ThemeMode } from '../modules/themeSettings';

const { t } = useI18n();
const { state } = useBackgroundSettings();
const { state: themeState } = useThemeSettings();

const loadingLogin = ref(false);
const loadingMain = ref(false);

const handleFile = async (event: Event, target: 'login' | 'main') => {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    try {
        target === 'login' ? loadingLogin.value = true : loadingMain.value = true;
        const dataUrl = await fileToDataUrl(file);
        if (target === 'login') {
            state.loginImage = dataUrl;
        } else {
            state.mainImage = dataUrl;
        }
    } finally {
        target === 'login' ? loadingLogin.value = false : loadingMain.value = false;
    }
};

const resetLogin = () => {
    state.loginImage = '';
    state.loginOpacity = 0.5;
};

const resetMain = () => {
    state.mainImage = '';
    state.mainOpacity = 1;
};

const themeOptions = [
    { label: '浅色', value: 'light' },
    { label: '深色', value: 'dark' },
    { label: '跟随系统', value: 'system' },
];

const onThemeChange = (val: ThemeMode) => {
    themeState.mode = val;
};
</script>

<template>
    <div id="settings-background-grid" class="grid gap-4 md:grid-cols-2 mb-4 p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700">
        <Card id="settings-login-card">
            <template #title>
                <span id="settings-login-title">登陆界面自定义背景图片</span>
            </template>
            <template #content>
                <div id="settings-login-content" class="space-y-3">
                    <div id="settings-login-upload" class="flex items-center gap-3">
                        <input id="settings-login-file" type="file" accept="image/*" @change="(e) => handleFile(e, 'login')" />
                        <Button id="settings-login-reset" :label="t('web.settings.reset') || 'Reset'" size="small" severity="secondary"
                            @click="resetLogin" :disabled="loadingLogin" />
                    </div>
                    <div id="settings-login-opacity">
                        <label id="settings-login-opacity-label" class="text-sm block mb-1">
                            {{ t('web.settings.opacity') || 'Opacity' }}: {{ Math.round(state.loginOpacity * 100) }}%
                        </label>
                        <Slider id="settings-login-opacity-slider" v-model="state.loginOpacity" :min="0" :max="1" :step="0.01" />
                    </div>
                </div>
            </template>
        </Card>

        <Card id="settings-main-card">
            <template #title>
                <span id="settings-main-title">仪表盘主界面自定义背景图片</span>
            </template>
            <template #content>
                <div id="settings-main-content" class="space-y-3">
                    <div id="settings-main-upload" class="flex items-center gap-3">
                        <input id="settings-main-file" type="file" accept="image/*" @change="(e) => handleFile(e, 'main')" />
                        <Button id="settings-main-reset" :label="t('web.settings.reset') || 'Reset'" size="small" severity="secondary"
                            @click="resetMain" :disabled="loadingMain" />
                    </div>
                    <div id="settings-main-opacity">
                        <label id="settings-main-opacity-label" class="text-sm block mb-1">
                            {{ t('web.settings.opacity') || 'Opacity' }}: {{ Math.round(state.mainOpacity * 100) }}%
                        </label>
                        <Slider id="settings-main-opacity-slider" v-model="state.mainOpacity" :min="0" :max="1" :step="0.01" />
                    </div>
                </div>
            </template>
        </Card>
    </div>

    <div id="settings-theme-wrapper" class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700">
        <Card id="settings-theme-card">
            <template #title> <span id="settings-theme-title">主题</span> </template>
            <template #content>
                <div id="settings-theme-content" class="space-y-2">
                    <label id="settings-theme-label" class="text-sm block">选择主题模式</label>
                    <Select id="settings-theme-select" v-model="themeState.mode" :options="themeOptions" optionLabel="label" optionValue="value"
                        class="w-full" @update:modelValue="onThemeChange" />
                </div>
            </template>
        </Card>
    </div>
</template>
