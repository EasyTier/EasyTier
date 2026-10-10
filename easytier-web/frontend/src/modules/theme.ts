// Console theme mode: light / dark / system, persisted in localStorage and
// applied by toggling the `app-dark` class PrimeVue and Tailwind key on.

export type ThemeMode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'console-theme-mode';

const media = window.matchMedia('(prefers-color-scheme: dark)');

export function storedThemeMode(): ThemeMode {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === 'light' || stored === 'dark' ? stored : 'system';
}

export function applyThemeMode(mode: ThemeMode) {
    localStorage.setItem(STORAGE_KEY, mode);
    const dark = mode === 'dark' || (mode === 'system' && media.matches);
    document.documentElement.classList.toggle('app-dark', dark);
}

export function initThemeMode() {
    applyThemeMode(storedThemeMode());
    media.addEventListener('change', () => {
        if (storedThemeMode() === 'system') {
            applyThemeMode('system');
        }
    });
}
