<script setup lang="ts">
import { TransitionPresets, useTransition } from '@vueuse/core'
import { TransitionFunc } from '~/types/components'

const props = withDefaults(defineProps<Props>(), {
  from: 0,
  duration: 1000,
  autoplay: true,
  eliminate: false,
  precision: -1,
  prefix: undefined,
  suffix: undefined,
  className: '',
  transition: TransitionFunc.easeInOutCubic,
})

const emits = defineEmits(['started', 'finished'])

interface Props {
  from?: number // 数值动画起始数值
  to?: number // 数值目标值
  duration?: number // 数值动画持续时间，单位 ms
  autoplay?: boolean // 是否自动开始动画
  precision?: number // 数值精度
  eliminate?: boolean // 是否消除末尾0
  prefix?: string // 前缀
  suffix?: string // 后缀
  className?: string // 数值文本样式
  transition?: TransitionFunc // 动画过渡效果
}

const source = ref(props.from)

watchEffect(() => {
  source.value = props.from
})

watch([() => props.from, () => props.to], () => {
  play()
})

onMounted(() => {
  play()
})

const outputValue = useTransition(source, {
  duration: props.duration,
  transition: TransitionPresets[props.transition],
  onFinished: () => emits('finished'),
  onStarted: () => emits('started'),
})

function play() {
  if (props.to !== undefined)
    source.value = props.to
}

const showValue = computed(() => {
  const { precision, eliminate, prefix, suffix, to } = props

  if (to === undefined)
    return suffix || 'N/A'

  const fixLength = precision === -1 ? to.toString().split('.')[1]?.length || 0 : precision
  const value = outputValue.value.toFixed(fixLength)
  return `${prefix || ''}${eliminate ? value.replace(/\.?0+$/, '') : value}${suffix || ''}`
})

defineExpose({
  play,
})
</script>

<template>
  <span :class="className">
    {{ showValue }}
  </span>
</template>
