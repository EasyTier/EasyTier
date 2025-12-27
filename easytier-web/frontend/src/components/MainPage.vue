<script setup lang="ts">
import { I18nUtils } from 'easytier-frontend-lib'
import { computed, onMounted, ref, onUnmounted, nextTick } from 'vue';
import { Button, TieredMenu } from 'primevue';
import { useRoute, useRouter } from 'vue-router';
import { useDialog } from 'primevue/usedialog';
import ChangePassword from './ChangePassword.vue';
import Icon from '../assets/easytier.png'
import { useI18n } from 'vue-i18n'
import ApiClient from '../modules/api';
import { useBackgroundSettings } from '../modules/backgroundSettings';

const { t } = useI18n()
const route = useRoute();
const router = useRouter();
const api = computed<ApiClient | undefined>(() => {
    try {
        return new ApiClient(atob(route.params.apiHost as string), () => {
            router.push({ name: 'login' });
        })
    } catch (e) {
        router.push({ name: 'login' });
    }
});

const dialog = useDialog();

const userMenu = ref();
const userMenuItems = ref([
    {
        label: t('web.main.change_password'),
        icon: 'pi pi-key',
        command: () => {
            console.log('File');
            let ret = dialog.open(ChangePassword, {
                props: {
                    modal: true,
                },
                data: {
                    api: api.value,
                }
            });

            console.log("return", ret)
        },
    },
    {
        label: t('web.main.logout'),
        icon: 'pi pi-sign-out',
        command: async () => {
            try {
                await api.value?.logout();
            } catch (e) {
                console.error("logout failed", e);
            }
            router.push({ name: 'login' });
        },
    },
])

const forceShowSideBar = ref(false)
const sidebarRef = ref<HTMLElement>()
const toggleButtonRef = ref<HTMLElement>()

// 处理点击外部区域关闭侧边栏
const handleClickOutside = (event: Event) => {
    const target = event.target as HTMLElement;

    // 如果侧边栏是隐藏的，不需要处理
    if (!forceShowSideBar.value) return;

    // 检查点击是否在侧边栏内部或切换按钮上
    const isClickInsideSidebar = sidebarRef.value?.contains(target);
    const isClickOnToggleButton = toggleButtonRef.value?.contains(target);

    // 如果点击在侧边栏外部且不在切换按钮上，则关闭侧边栏
    if (!isClickInsideSidebar && !isClickOnToggleButton) {
        forceShowSideBar.value = false;
    }
};

// 切换侧边栏显示状态
const toggleSidebar = () => {
    forceShowSideBar.value = !forceShowSideBar.value;
};

// 点击背景遮罩关闭侧边栏
const closeSidebar = () => {
    forceShowSideBar.value = false;
};

onMounted(async () => {
    // 等待 DOM 渲染完成后添加事件监听器
    await nextTick();
    document.addEventListener('click', handleClickOutside);
});

onUnmounted(() => {
    document.removeEventListener('click', handleClickOutside);
});

const { mainBackgroundStyle, state: bgState } = useBackgroundSettings();
const chromeOpacity = computed(() => Math.min((bgState.mainOpacity ?? 0) + 0.25, 1));

</script>

<!-- https://flowbite.com/docs/components/sidebar/#sidebar-with-navbar -->
<template>
    <div id="main-wrapper" class="main-wrapper" :style="mainBackgroundStyle">
    <nav
        class="fixed top-0 z-50 w-full bg-white border-b border-gray-200 dark:bg-gray-800 dark:border-gray-700 top-navbar"
        :style="{ opacity: chromeOpacity }" id="main-top-navbar">
        <div class="px-3 py-3 lg:px-5 lg:pl-3" id="main-nav-inner">
            <div class="flex items-center justify-between" id="main-nav-row">
                <div class="flex items-center justify-start rtl:justify-end" id="main-nav-left">
                    <div class="sm:hidden" id="main-nav-toggle-container">
                        <Button ref="toggleButtonRef" id="main-nav-toggle-button" type="button" aria-haspopup="true" icon="pi pi-list"
                            variant="text" size="large" severity="contrast" @click="toggleSidebar" />
                    </div>
                    <a href="https://easytier.top" class="flex ms-2 md:me-24" id="main-brand-link">
                        <img :src="Icon" class="h-9 me-3" alt="FlowBite Logo" id="main-brand-logo" />
                        <span
                            class="self-center text-xl font-semibold sm:text-2xl whitespace-nowrap dark:text-white" id="main-brand-name">EasyTier</span>
                    </a>
                </div>
                <div class="flex items-center" id="main-nav-right">
                    <div class="language-switch" id="main-language-switch">
                        <Button id="main-language-button" icon="pi pi-language" @click="I18nUtils.toggleLanguage" rounded severity="contrast" />
                    </div>

                    <div class="flex items-center ms-3" id="main-user-menu-wrapper">
                        <div id="main-user-menu">
                            <Button id="main-user-menu-button" type="button" @click="userMenu.toggle($event)" aria-haspopup="true"
                                aria-controls="user-menu" icon="pi pi-user" raised rounded />
                            <TieredMenu ref="userMenu" id="user-menu" :model="userMenuItems" popup />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- 背景遮罩 - 只在侧边栏显示时显示 -->
    <div v-if="forceShowSideBar" id="main-sidebar-mask" class="fixed inset-0 z-30 bg-black bg-opacity-50 sm:hidden" @click="closeSidebar">
    </div>

    <aside ref="sidebarRef" id="logo-sidebar"
        class="fixed top-1 left-0 z-40 w-64 h-screen pt-20 transition-transform bg-white border-r border-gray-201 sm:translate-x-0 dark:bg-gray-800 dark:border-gray-700"
        :class="{ '-translate-x-full': !forceShowSideBar }" aria-label="Sidebar"
        :style="{ opacity: chromeOpacity }">
        <div class="h-full px-3 pb-4 overflow-y-auto bg-white dark:bg-gray-800" id="main-sidebar-content">
            <ul class="space-y-2 font-medium h-full flex flex-col" id="main-sidebar-list">
                <li id="main-sidebar-dashboard-item">
                    <Button id="main-sidebar-dashboard-btn" variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'dashboard' })">
                        <i id="main-sidebar-dashboard-icon" class="pi pi-chart-pie text-xl"></i>
                        <span id="main-sidebar-dashboard-text" class="mb-0.5">{{ t('web.main.dashboard') }}</span>
                    </Button>
                </li>
                <li id="main-sidebar-device-list-item">
                    <Button id="main-sidebar-device-list-btn" variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'deviceList' })">
                        <i id="main-sidebar-device-list-icon" class="pi pi-server text-xl"></i>
                        <span id="main-sidebar-device-list-text" class="mb-0.5">{{ t('web.main.device_list') }}</span>
                    </Button>
                </li>
                <li id="main-sidebar-network-graph-item">
                    <Button id="main-sidebar-network-graph-btn" variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'networkGraph' })">
                        <i id="main-sidebar-network-graph-icon" class="pi pi-share-alt text-xl"></i>
                        <span id="main-sidebar-network-graph-text" class="mb-0.5">Network Graph / 网络拓扑图</span>
                    </Button>
                </li>
                <li id="main-sidebar-settings-item">
                    <Button id="main-sidebar-settings-btn" variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'settings' })">
                        <i id="main-sidebar-settings-icon" class="pi pi-cog text-xl"></i>
                        <span id="main-sidebar-settings-text" class="mb-0.5">Setting</span>
                    </Button>
                </li>
                <li class="mt-auto" id="main-sidebar-logout-item">
                    <Button id="main-sidebar-logout-btn" variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="danger" @click="router.push({ name: 'login' })">
                        <i id="main-sidebar-logout-icon" class="pi pi-sign-out text-xl"></i>
                        <span id="main-sidebar-logout-text" class="mb-0.5">{{ t('web.main.logout') || 'Logout' }}</span>
                    </Button>
                </li>
            </ul>
        </div>
    </aside>

    <div class="p-4 sm:ml-64" id="main-content-wrapper">
        <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700" id="main-content-frame">
            <div class="grid grid-cols-1 gap-4" id="main-content-grid">
                <RouterView id="main-router-view" v-slot="{ Component }">
                    <component :is="Component" :api="api" />
                </RouterView>
            </div>
        </div>
    </div>
    </div>
</template>

<style scoped>
.main-wrapper {
    min-height: 100vh;
    position: relative;
}

.main-wrapper::before {
    content: "";
    position: fixed;
    inset: 0;
    background-image: var(--main-bg, none);
    background-size: cover;
    background-position: center;
    opacity: var(--main-opacity, 1);
    z-index: -1;
}

.sidebar-button {
    text-align: left;
    justify-content: left;
}
</style>
