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

</script>

<!-- https://flowbite.com/docs/components/sidebar/#sidebar-with-navbar -->
<template>
    <nav
        class="fixed top-0 z-50 w-full bg-white border-b border-gray-200 dark:bg-gray-800 dark:border-gray-700 top-navbar">
        <div class="px-3 py-3 lg:px-5 lg:pl-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center justify-start rtl:justify-end">
                    <div class="sm:hidden">
                        <Button ref="toggleButtonRef" type="button" aria-haspopup="true" icon="pi pi-list"
                            variant="text" size="large" severity="contrast" @click="toggleSidebar" />
                    </div>
                    <a href="https://easytier.top" class="flex ms-2 md:me-24">
                        <img :src="Icon" class="h-9 me-3" alt="FlowBite Logo" />
                        <span
                            class="self-center text-xl font-semibold sm:text-2xl whitespace-nowrap dark:text-white">EasyTier</span>
                    </a>
                </div>
                <div class="flex items-center">
                    <div class="language-switch">
                        <Button icon="pi pi-language" @click="I18nUtils.toggleLanguage" rounded severity="contrast" />
                    </div>

                    <div class="flex items-center ms-3">
                        <div>
                            <Button type="button" @click="userMenu.toggle($event)" aria-haspopup="true"
                                aria-controls="user-menu" icon="pi pi-user" raised rounded />
                            <TieredMenu ref="userMenu" id="user-menu" :model="userMenuItems" popup />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- 背景遮罩 - 只在侧边栏显示时显示 -->
    <div v-if="forceShowSideBar" class="fixed inset-0 z-30 bg-black bg-opacity-50 sm:hidden" @click="closeSidebar">
    </div>

    <aside ref="sidebarRef" id="logo-sidebar"
        class="fixed top-1 left-0 z-40 w-64 h-screen pt-20 transition-transform bg-white border-r border-gray-201 sm:translate-x-0 dark:bg-gray-800 dark:border-gray-700"
        :class="{ '-translate-x-full': !forceShowSideBar }" aria-label="Sidebar">
        <div class="h-full px-3 pb-4 overflow-y-auto bg-white dark:bg-gray-800">
            <ul class="space-y-2 font-medium">
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'dashboard' })">
                        <i class="pi pi-chart-pie text-xl"></i>
                        <span class="mb-0.5">{{ t('web.main.dashboard') }}</span>
                    </Button>
                </li>
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'deviceList' })">
                        <i class="pi pi-server text-xl"></i>
                        <span class="mb-0.5">{{ t('web.main.device_list') }}</span>
                    </Button>
                </li>
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'login' })">
                        <i class="pi pi-sign-in text-xl"></i>
                        <span class="mb-0.5">{{ t('web.main.login_page') }}</span>
                    </Button>
                </li>
            </ul>
        </div>
    </aside>

    <div class="p-4 sm:ml-64">
        <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700">
            <div class="grid grid-cols-1 gap-4">
                <RouterView v-slot="{ Component }">
                    <component :is="Component" :api="api" />
                </RouterView>
            </div>
        </div>
    </div>
</template>

<style scoped>
.sidebar-button {
    text-align: left;
    justify-content: left;
}
</style>
