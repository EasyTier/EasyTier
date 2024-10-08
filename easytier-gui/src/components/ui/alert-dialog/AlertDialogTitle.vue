<script setup lang="ts">
import { AlertDialogTitle, type AlertDialogTitleProps } from 'radix-vue'
import { computed, type HTMLAttributes } from 'vue'
import { cn } from '~/lib/utils'

const props = defineProps<AlertDialogTitleProps & { class?: HTMLAttributes['class'] }>()

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})
</script>

<template>
  <AlertDialogTitle
    v-bind="delegatedProps"
    :class="cn('text-lg font-semibold', props.class)"
  >
    <slot />
  </AlertDialogTitle>
</template>
