const MUST_CHANGE_PASSWORD_STORAGE_KEY = 'auth.mustChangePassword';

export const getMustChangePasswordFlag = (): boolean | null => {
    const value = sessionStorage.getItem(MUST_CHANGE_PASSWORD_STORAGE_KEY);
    if (value === null) {
        return null;
    }

    return value === 'true';
};

export const setMustChangePasswordFlag = (value: boolean) => {
    sessionStorage.setItem(MUST_CHANGE_PASSWORD_STORAGE_KEY, value ? 'true' : 'false');
};

export const clearMustChangePasswordFlag = () => {
    sessionStorage.removeItem(MUST_CHANGE_PASSWORD_STORAGE_KEY);
};
