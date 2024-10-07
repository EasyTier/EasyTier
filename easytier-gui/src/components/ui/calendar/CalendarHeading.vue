<script lang="ts" setup>
import { CalendarHeading, type CalendarHeadingProps, useForwardProps } from 'radix-vue'
import { computed, type HTMLAttributes } from 'vue'
import { cn } from '~/lib/utils'

const props = defineProps<CalendarHeadingProps & { class?: HTMLAttributes['class'] }>()

const delegatedProps = computed(() => {
  const { class: _, ...delegated } = props

  return delegated
})

const forwardedProps = useForwardProps(delegatedProps)
</script>

<template>
  <CalendarHeading

    :class="cn('text-sm font-medium', props.class)"
    v-bind="forwardedProps"
  >
    <!-- <slot :heading-value>
      {{ headingValue }}
    </slot> -->
  </CalendarHeading>
</template>
