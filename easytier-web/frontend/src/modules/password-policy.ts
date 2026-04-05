export type PasswordValidationReasonKey =
    | 'web.common.password_empty'
    | 'web.common.password_min_length'
    | 'web.common.password_too_weak';

export interface PasswordValidationResult {
    valid: boolean;
    reasonKey?: PasswordValidationReasonKey;
}

const PASSWORD_MIN_LENGTH = 8;

export const countPasswordClasses = (password: string) => {
    let count = 0;

    if (/[a-z]/.test(password)) {
        count += 1;
    }
    if (/[A-Z]/.test(password)) {
        count += 1;
    }
    if (/\d/.test(password)) {
        count += 1;
    }
    if (/[^A-Za-z0-9\s]/.test(password)) {
        count += 1;
    }

    return count;
};

export const validatePasswordStrength = (password: string): PasswordValidationResult => {
    if (password.trim().length === 0) {
        return {
            valid: false,
            reasonKey: 'web.common.password_empty',
        };
    }

    if (password.length < PASSWORD_MIN_LENGTH) {
        return {
            valid: false,
            reasonKey: 'web.common.password_min_length',
        };
    }

    if (countPasswordClasses(password) < 2) {
        return {
            valid: false,
            reasonKey: 'web.common.password_too_weak',
        };
    }

    return { valid: true };
};
