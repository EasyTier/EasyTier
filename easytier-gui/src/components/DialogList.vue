<script setup lang="ts">

</script>

<template>
  <AddInstanceBase />
  <AppAutostart />
  <CloseConfirm v-if="isTauri" />
</template>

<style scoped lang="postcss"></style>
