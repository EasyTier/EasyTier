<script setup lang="ts">
const instanceStore = useInstanceStore()
const { selectedId } = storeToRefs(instanceStore)

const filterInstanceValue = ref('')
</script>

<template>
  <div :class="isMobile ? 'h-full' : 'flex h-full'">
    <div
      v-if="!isMobile || !selectedId"
      :class="`overflow-hidden h-full flex flex-col ${isMobile ? 'm-auto' : 'min-w-72'}`"
    >
      <InstanceAction v-model="filterInstanceValue" />
      <InstanceList :filter="filterInstanceValue" />
    </div>
    <div v-if="!isMobile || selectedId" class="w-full h-full">
      <InstanceDisplay />
    </div>
  </div>
</template>
