import type { UseModule } from '~/types/modules'

export const install: UseModule = () => {
  if (isProd) {
    document.addEventListener('keydown', (event) => {
      if (
        event.key === 'F5'
        || (event.ctrlKey && event.key === 'r')
        || (event.metaKey && event.key === 'r')
      ) {
        event.preventDefault()
      }
    })

    document.addEventListener('contextmenu', (event) => {
      event.preventDefault()
    })
  }
}
