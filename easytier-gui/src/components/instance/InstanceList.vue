<script setup lang="ts">
import { FileCog, Plus } from 'lucide-vue-next'

interface InstanceListProps {
  filter: string
}

const props = defineProps<InstanceListProps>()
const instanceStore = useInstanceStore()
const { selectedId, instances } = storeToRefs(instanceStore)

const appStore = useAppStore()

const filterInstances = computed(() => instances?.value.filter(instance => instance.name.toLowerCase().includes(props.filter.toLowerCase()) || instance.ipv4?.toLowerCase().includes(props.filter.toLowerCase())) || [])

function selectInstance(id: string) {
  instanceStore.setSelectedId(selectedId.value === id ? '' : id)
}
</script>

<template>
  <ScrollArea v-if="instances.length" class="h-full flex">
    <div class="flex flex-1 flex-col gap-2 p-2 pt-0">
      <TransitionGroup name="list" appear>
        <button
          v-for="instance of filterInstances" :key="instance.id" :class="cn(
            'flex flex-col items-start gap-2 rounded-lg border p-3 text-left text-sm transition-all hover:bg-accent',
            selectedId === instance.id && 'bg-muted',
          )" @click="selectInstance(instance.id)"
        >
          <div class="w-full flex flex-col gap-1">
            <div class="flex items-center">
              <div class="w-full flex items-center gap-2">
                <Tooltip>
                  <TooltipTrigger class="max-w-[calc(100%-1rem)] truncate font-semibold">
                    {{ instance.name }}
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>{{ instance.name }}</p>
                  </TooltipContent>
                </Tooltip>

                <span v-if="instance.status" class="h-2 w-2 flex rounded-full bg-green-600" />
              </div>
              <!-- <div
                :class="cn(
                  'ml-auto text-xs',
                  selectedId === instance.id
                    ? 'text-foreground'
                    : 'text-muted-foreground',
                )"
              >
                {{ }}
              </div> -->
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <Badge
              v-if="instance.ipv4 && instance.status" variant="outline"
              :class="selectedId === instance.id ? 'text-foreground' : 'text-muted-foreground'"
            >
              {{ instance.ipv4 }}
            </Badge>
            <Badge
              v-if="instance.stats.length && instance.status" variant="secondary"
              :class="`space-x-2 ${selectedId === instance.id ? 'text-foreground' : 'text-muted-foreground'}`"
            >
              <span>{{ humanStreamSize(instance?.stats[instance?.stats.length - 1].peers.reduce((accumulator,
                                                                                                 currentObject) => accumulator + currentObject.up, 0) || 0) }}</span>
              <Separator class="!bg-transparent" orientation="vertical" label="/" />
              <span>{{ humanStreamSize(instance?.stats[instance?.stats.length - 1].peers.reduce((accumulator,
                                                                                                 currentObject) => accumulator + currentObject.down, 0) || 0) }}</span>
            </Badge>
          </div>
        </button>
      </TransitionGroup>
    </div>
  </ScrollArea>
  <div v-else class="m-2 mt-0 border rounded-lg border-dashed border-muted flex items-center justify-center h-full">
    <div class="flex flex-wrap space-x-2 items-center justify-center w-full">
      <Button variant="link" class="space-x-4" @click="appStore.setAddInstanceDialogVisible(true)">
        <Plus class="w-6 h-6" />
        <Separator orientation="vertical" label="/" />
        <FileCog class="w-6 h-6" />
      </Button>
    </div>
  </div>
</template>

<style scoped lang="postcss">
.list-move,
.list-enter-active,
.list-leave-active {
  transition: all 0.5s ease;
}

.list-enter-from,
.list-leave-to {
  opacity: 0;
  transform: translateY(15px);
}

.list-leave-active {
  position: absolute;
}
</style>
