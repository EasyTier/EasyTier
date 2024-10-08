<script setup lang="ts">
import { AccordionContent, type AccordionContentProps } from 'radix-vue'
import { computed, type HTMLAttributes } from 'vue'
import { cn } from '~/lib/utils'

const props = defineProps<AccordionContentProps & { class?: HTMLAttributes['class'] }>()

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})
</script>

<template>
  <AccordionContent
    v-bind="delegatedProps"
    class="data-[state=closed]:animate-accordion-up data-[state=open]:animate-accordion-down overflow-hidden text-sm"
  >
    <div :class="cn('pb-4 pt-0', props.class)">
      <slot />
    </div>
  </AccordionContent>
</template>
