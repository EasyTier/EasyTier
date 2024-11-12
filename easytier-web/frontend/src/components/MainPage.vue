<script setup lang="ts">
import { Api, I18nUtils } from 'easytier-frontend-lib'
import { computed, onMounted, ref } from 'vue';
import { Button, TieredMenu } from 'primevue';
import { useRoute, useRouter } from 'vue-router';
import { useDialog } from 'primevue/usedialog';
import ChangePassword from './ChangePassword.vue';
import Icon from '../assets/easytier.png'

const route = useRoute();
const router = useRouter();
const api = computed<Api.ApiClient | undefined>(() => {
    try {
        return new Api.ApiClient(atob(route.params.apiHost as string), () => {
            router.push({ name: 'login' });
        })
    } catch (e) {
        router.push({ name: 'login' });
    }
});

const dialog = useDialog();

onMounted(async () => {
    await I18nUtils.loadLanguageAsync('cn')
});

const userMenu = ref();
const userMenuItems = ref([
    {
        label: 'Change Password',
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
        label: 'Logout',
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

</script>

<!-- https://flowbite.com/docs/components/sidebar/#sidebar-with-navbar -->
<template>
    <nav class="fixed top-0 z-50 w-full bg-white border-b border-gray-200 dark:bg-gray-800 dark:border-gray-700">
        <div class="px-3 py-3 lg:px-5 lg:pl-3">
            <div class="flex items-center justify-between">
                <div class="flex items-center justify-start rtl:justify-end">
                    <div class="sm:hidden">
                        <Button type="button" aria-haspopup="true" icon="pi pi-list" variant="text" size="large"
                            severity="contrast" @click="forceShowSideBar = !forceShowSideBar" />
                    </div>
                    <a href="https://easytier.top" class="flex ms-2 md:me-24">
                        <img :src="Icon" class="h-9 me-3" alt="FlowBite Logo" />
                        <span
                            class="self-center text-xl font-semibold sm:text-2xl whitespace-nowrap dark:text-white">EasyTier</span>
                    </a>
                </div>
                <div class="flex items-center">
                    <div class="flex items-center ms-3">
                        <div>
                            <Button type="button" @click="userMenu.toggle($event)" aria-haspopup="true"
                                aria-controls="user-menu" icon="pi pi-user" raised rounded />
                            <TieredMenu ref="userMenu" id="user-menu" :model="userMenuItems" popup />
                        </div>
                        <div class="z-50 hidden my-4 text-base list-none bg-white divide-y divide-gray-100 rounded shadow dark:bg-gray-700 dark:divide-gray-600"
                            id="dropdown-user">
                            <div class="px-4 py-3" role="none">
                                <p class="text-sm text-gray-900 dark:text-white" role="none">
                                    Neil Sims
                                </p>
                                <p class="text-sm font-medium text-gray-900 truncate dark:text-gray-300" role="none">
                                    neil.sims@flowbite.com
                                </p>
                            </div>
                            <ul class="py-1" role="none">
                                <li>
                                    <a href="#"
                                        class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-600 dark:hover:text-white"
                                        role="menuitem">Dashboard</a>
                                </li>
                                <li>
                                    <a href="#"
                                        class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-600 dark:hover:text-white"
                                        role="menuitem">Settings</a>
                                </li>
                                <li>
                                    <a href="#"
                                        class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-600 dark:hover:text-white"
                                        role="menuitem">Earnings</a>
                                </li>
                                <li>
                                    <a href="#"
                                        class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-600 dark:hover:text-white"
                                        role="menuitem">Sign out</a>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <aside id="logo-sidebar"
        class="fixed top-1 left-0 z-40 w-64 h-screen pt-20 transition-transform bg-white border-r border-gray-201 sm:translate-x-0 dark:bg-gray-800 dark:border-gray-700"
        :class="{ '-translate-x-full': !forceShowSideBar }" aria-label="Sidebar">
        <div class="h-full px-3 pb-4 overflow-y-auto bg-white dark:bg-gray-800">
            <ul class="space-y-2 font-medium">
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'dashboard' })">
                        <i class="pi pi-chart-pie text-xl"></i>
                        <span class="mb-0.5">DashBoard</span>
                    </Button>
                </li>
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'deviceList' })">
                        <i class="pi pi-server text-xl"></i>
                        <span class="mb-0.5">Devices</span>
                    </Button>
                </li>
                <li>
                    <Button variant="text" class="w-full justify-start gap-x-3 pl-1.5 sidebar-button"
                        severity="contrast" @click="router.push({ name: 'login' })">
                        <i class="pi pi-sign-in text-xl"></i>
                        <span class="mb-0.5">Login Page</span>
                    </Button>
                </li>
            </ul>
        </div>
    </aside>

    <div class="p-4 sm:ml-64">
        <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700 mt-14">
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
