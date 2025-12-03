import { reactive, watchEffect } from 'vue';

export type ThemeMode = 'light' | 'dark' | 'system';

const state = reactive({
  mode: (localStorage.getItem('theme:mode') as ThemeMode) || 'system',
});

let initialized = false;

function applyTheme() {
  const root = document.documentElement;
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const enableDark = state.mode === 'dark' || (state.mode === 'system' && prefersDark);
  root.classList.toggle('dark', enableDark);
  root.style.colorScheme = enableDark ? 'dark' : 'light';
}

export function useThemeSettings() {
  if (!initialized) {
    initialized = true;
    watchEffect(() => {
      localStorage.setItem('theme:mode', state.mode);
      applyTheme();
    });

    // React to system changes when in system mode
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener('change', () => {
      if (state.mode === 'system') applyTheme();
    });
  } else {
    applyTheme();
  }

  return { state, applyTheme };
}
