<script setup lang="ts">
const { t } = useI18n()
const etVersion = ref<string | null>()

onBeforeMount(async () => {
  etVersion.value = await easytierVersion()
})
</script>

<template>
  <div class="pb-2 space-y-2">
    <div class="space-y-2 text-center">
      <div class="space-x-2 py-6">
        <div class="text-3xl font-bold">
          EasyTier
        </div>
        <div class="space-x-2">
          <Badge class="space-x-2 font-normal text-xs px-1.5 py-0.5">
            Gui: {{ `v${pkg.version}` }}
          </Badge>
          <Badge variant="secondary" class="space-x-2 font-normal text-xs px-1.5 py-0.5">
            Core: {{ `v${etVersion}` }}
          </Badge>
        </div>
      </div>
      <Separator />
      <p class="text-sm text-muted-foreground">
        {{ t('component.about.description') }}
      </p>
      <div class="flex flex-wrap space-x-2 justify-center">
        <Image src="https://img.shields.io/github/license/EasyTier/EasyTier" alt="badge" />
        <Image src="https://img.shields.io/github/v/release/EasyTier/EasyTier" alt="badge" />
        <Image src="https://img.shields.io/github/last-commit/EasyTier/EasyTier" alt="badge" />
      </div>
    </div>
  </div>
</template>

<style lang="postcss" scoped>
</style>
