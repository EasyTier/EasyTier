<script setup lang="ts">
interface Props {
  src?: string
  alt?: string
  draggable?: boolean
}
const props = withDefaults(defineProps<Props>(), {
  draggable: false,
})
</script>

<template>
  <img :src="props.src" :alt="props.alt" class="select-none" :draggable="props.draggable">
</template>

<style lang="postcss" scoped></style>
