<script setup lang="ts">
import { EventType } from '~/types/network'

const props = defineProps<{
  event: {
    [key: string]: any
  }
}>()
const { t } = useI18n()

const eventKey = computed(() => {
  const key = Object.keys(props.event)[0]
  return Object.keys(EventType).includes(key) ? key : 'Unknown'
})

const eventValue = computed(() => {
  const value = props.event[eventKey.value]
  return typeof value === 'object' ? value : value
})
</script>

<template>
  <Fieldset :legend="t(`event.${eventKey}`)">
    <template v-if="eventKey !== 'Unknown'">
      <div v-if="event.DhcpIpv4Changed">
        {{ `${eventValue[0]} -> ${eventValue[1]}` }}
      </div>
      <pre v-else>{{ eventValue }}</pre>
    </template>
    <pre v-else>{{ eventValue }}</pre>
  </Fieldset>
</template>
