import { computed, reactive, watch } from 'vue';

const DEFAULT_LOGIN_BG =
  'https://www.polyu.edu.hk/-/media/department/home/gallery/campus-environment/c0123.jpg';

type BgState = {
  loginImage: string;
  loginOpacity: number;
  mainImage: string;
  mainOpacity: number;
};

const state = reactive<BgState>({
  loginImage: localStorage.getItem('bg:login:image') || '',
  loginOpacity: Number(localStorage.getItem('bg:login:opacity') || '0.5'),
  mainImage: localStorage.getItem('bg:main:image') || '',
  mainOpacity: Number(localStorage.getItem('bg:main:opacity') || '1'),
});

watch(
  () => state.loginImage,
  (val) => localStorage.setItem('bg:login:image', val || '')
);
watch(
  () => state.mainImage,
  (val) => localStorage.setItem('bg:main:image', val || '')
);
watch(
  () => state.loginOpacity,
  (val) => localStorage.setItem('bg:login:opacity', String(val))
);
watch(
  () => state.mainOpacity,
  (val) => localStorage.setItem('bg:main:opacity', String(val))
);

export function useBackgroundSettings() {
  const loginBackgroundStyle = computed(() => ({
    '--login-bg': `url(${state.loginImage || DEFAULT_LOGIN_BG})`,
    '--login-opacity': state.loginOpacity.toString(),
  }));

  const mainBackgroundStyle = computed(() => {
    if (!state.mainImage) {
      return {};
    }
    return {
      '--main-bg': `url(${state.mainImage})`,
      '--main-opacity': state.mainOpacity.toString(),
    };
  });

  return {
    state,
    loginBackgroundStyle,
    mainBackgroundStyle,
  };
}

export async function fileToDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error);
    reader.readAsDataURL(file);
  });
}
