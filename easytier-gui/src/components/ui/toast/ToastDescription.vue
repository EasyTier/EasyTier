<script setup lang="ts">
import { ToastDescription, type ToastDescriptionProps } from 'radix-vue'
import { computed, type HTMLAttributes } from 'vue'
import { cn } from '~/lib/utils'

const props = defineProps<ToastDescriptionProps & { class?: HTMLAttributes['class'] }>()

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})
</script>

<template>
  <ToastDescription :class="cn('text-sm opacity-90', props.class)" v-bind="delegatedProps">
    <slot />
  </ToastDescription>
</template>
