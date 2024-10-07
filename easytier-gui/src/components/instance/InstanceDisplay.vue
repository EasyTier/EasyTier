<script setup lang="ts">
import { BookA, ChevronLeft, FileClock, MoreVertical, Share2, Trash2 } from 'lucide-vue-next'
import { DropdownMenuPortal } from '~/components/ui/dropdown-menu'
import { useToast } from '~/components/ui/toast/use-toast'

const { toast } = useToast()
const { t } = useI18n()
const instanceStore = useInstanceStore()
const appStore = useAppStore()
const { selectedId, currentInstance } = storeToRefs(instanceStore)
const { logLevel } = storeToRefs(appStore)

const instanceStatus = computed(() => currentInstance.value?.status)

const levels = ['off', 'warn', 'info', 'debug', 'trace']
function back() {
  if (isMobile.value)
    instanceStore.setSelectedId('')
}

async function toggleStatus(id: string) {
  try {
    instanceStore.toggleInstanceStatus(id)
  }
  catch (e) {
    toast({
      title: t('toast.error.operateInstance'),
      variant: 'destructive',
      description: h('div', { class: 'whitespace-pre-wrap', innerHTML: e }),
    })
  }
}

async function openLogDir() {
  if (isTauri) {
    const { appLogDir } = await import('@tauri-apps/api/path')
    const { open } = await import('@tauri-apps/plugin-shell')
    await open(await appLogDir())
  }
}

function setLevel(level: string) {
  // @ts-expect-error ignore
  logLevel.value = level
}
</script>

<template>
  <div class="p-2 h-full w-full overflow-hidden">
    <template v-if="selectedId || isMobile">
      <div class="flex flex-row items-center justify-between">
        <div class="flex items-center">
          <Tooltip v-if="isMobile">
            <TooltipTrigger as-child>
              <Button variant="ghost" size="icon" @click="back()">
                <ChevronLeft class="size-4" />
                <span class="sr-only">{{ t('component.instance.display.back') }}</span>
              </Button>
            </TooltipTrigger>
            <TooltipContent>{{ t('component.instance.display.back') }}</TooltipContent>
          </Tooltip>
        </div>
        <div class="flex items-center">
          <Switch :checked="instanceStatus" @update:checked="toggleStatus(selectedId)" />
          <Separator orientation="vertical" class="mx-2 h-6" />
          <DropdownMenu>
            <DropdownMenuTrigger as-child>
              <Button variant="ghost" size="icon">
                <MoreVertical class="size-4" />
                <span class="sr-only">{{ t('component.instance.display.more') }}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>{{ t('component.instance.display.instanceAction') }}</DropdownMenuLabel>
              <DropdownMenuSub>
                <DropdownMenuSubTrigger>
                  <FileClock class="mr-2 h-4 w-4" />{{ t('component.instance.display.log.title') }}
                </DropdownMenuSubTrigger>
                <DropdownMenuPortal>
                  <DropdownMenuSubContent>
                    <DropdownMenuItem v-for="level in levels" :key="level" @click="setLevel(level)">
                      <span>{{ t(`component.instance.display.log.${level}`) }}</span>
                      <DropdownMenuShortcut v-if="logLevel === level">
                        √
                      </DropdownMenuShortcut>
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem @click="openLogDir()">
                      <span>{{ t('component.instance.display.log.open') }}</span>
                    </DropdownMenuItem>
                  </DropdownMenuSubContent>
                </DropdownMenuPortal>
              </DropdownMenuSub>
              <DropdownMenuItem v-show="false">
                <Share2 class="mr-2 h-4 w-4" />{{ t('component.instance.display.share') }}
              </DropdownMenuItem>
              <DropdownMenuItem
                v-if="isTauri && !platformIsMobile"
                @click="appStore.setAppAutostartDialogVisible(true)"
              >
                <BookA class="mr-2 h-4 w-4" />{{ t('component.instance.display.autostart') }}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem @click="instanceStore.deleteInstance(selectedId)">
                <Trash2 class="mr-2 h-4 w-4" />{{ t('component.instance.display.delete') }}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      <div class="w-full h-full mt-2 overflow-hidden">
        <InstanceStatus />
      </div>
    </template>
    <template v-else>
      <About />
    </template>
  </div>
</template>

<style lang="postcss" scoped></style>
