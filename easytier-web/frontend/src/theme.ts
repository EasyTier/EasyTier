import { definePreset } from '@primeuix/themes';
import Aura from '@primeuix/themes/aura';

const surface = {
    0: '#ffffff', 50: '#f7f8f9', 100: '#f0f2f4', 200: '#e3e6e9',
    300: '#d0d5da', 400: '#9ba4ae', 500: '#697581', 600: '#4e5965',
    700: '#38434e', 800: '#242e38', 900: '#18212a', 950: '#10171e',
};

export default definePreset(Aura, {
    semantic: {
        primary: {
            50: '{emerald.50}', 100: '{emerald.100}', 200: '{emerald.200}',
            300: '{emerald.300}', 400: '{emerald.400}', 500: '{emerald.500}',
            600: '{emerald.600}', 700: '{emerald.700}', 800: '{emerald.800}',
            900: '{emerald.900}', 950: '{emerald.950}',
        },
        colorScheme: {
            light: {
                surface,
                primary: { color: '{primary.700}', inverseColor: '#ffffff', hoverColor: '{primary.800}', activeColor: '{primary.900}' },
                highlight: { background: '{primary.50}', focusBackground: '{primary.100}', color: '{primary.700}', focusColor: '{primary.800}' },
            },
            dark: { surface },
        },
    },
});
