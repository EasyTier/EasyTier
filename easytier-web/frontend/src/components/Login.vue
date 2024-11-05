<template>
    <div class="flex items-center justify-center min-h-screen bg-gray-50">
        <div class="w-full max-w-md p-4 space-y-4">
            <h2 class="text-2xl font-semibold text-center">登录</h2>
            <div class="flex flex-col space-y-2">
                <InputText type="text" v-model="username"
                    class="w-full border border-gray-300 p-2 rounded-md focus:ring focus:ring-blue-500"
                    placeholder="用户名" />
                <InputText type="password" v-model="password"
                    class="w-full border border-gray-300 p-2 rounded-md focus:ring focus:ring-blue-500"
                    placeholder="密码" />
            </div>
            <Button label="登录" class="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 rounded-md"
                @click="handleLogin" />
        </div>
    </div>
</template>

<script setup>
import { ref } from 'vue';
import { InputText, Button } from 'primevue';

const username = ref('');
const password = ref('');

const handleLogin = () => {
    // 这里可以添加登录逻辑，比如调用API
    console.log('登录', username.value, password.value);
    // 验证用户名和密码
    if (username.value === 'admin' && password.value === 'admin') {
        alert('登录成功');
        // 跳转到主页或其他页面
    } else {
        alert('用户名或密码错误');
    }
};
</script>

<style>
/* 这里可以添加一些自定义的Tailwind CSS样式 */
</style>