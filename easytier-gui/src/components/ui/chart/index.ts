export { default as ChartCrosshair } from './ChartCrosshair.vue'
export { default as ChartLegend } from './ChartLegend.vue'
export { default as ChartSingleTooltip } from './ChartSingleTooltip.vue'
export { default as ChartTooltip } from './ChartTooltip.vue'

export function defaultColors(count: number = 3) {
  const quotient = Math.floor(count / 2)
  const remainder = count % 2

  const primaryCount = quotient + remainder
  const secondaryCount = quotient
  return [
    ...Array.from(Array.from({ length: primaryCount }).keys()).map(i => `hsl(var(--vis-primary-color) / ${1 - (1 / primaryCount) * i})`),
    ...Array.from(Array.from({ length: secondaryCount }).keys()).map(i => `hsl(var(--vis-secondary-color) / ${1 - (1 / secondaryCount) * i})`),
  ]
}

export * from './interface'
