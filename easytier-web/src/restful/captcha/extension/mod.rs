pub mod axum_tower_sessions;

use super::base::captcha::AbstractCaptcha;
use super::builder::spec::SpecCaptcha;
use super::{CaptchaFont, NewCaptcha};

/// 验证码工具类 - Captcha Utils
///
/// 默认使用[SpecCaptcha]（静态PNG字母验证码）作为验证码实现，用户也可以指定其他实现了[AbstractCaptcha]的类型。
///
/// Use [SpecCaptcha] (static PNG-format alphabetical Captcha) as the default implement of the Captcha service. Users may use other implementation of [AbstractCaptcha] they prefer.
///
pub struct CaptchaUtil<T: AbstractCaptcha = SpecCaptcha> {
    captcha_instance: T,
}

impl<T: AbstractCaptcha> NewCaptcha for CaptchaUtil<T> {
    fn new() -> Self {
        Self {
            captcha_instance: T::new(),
        }
    }

    fn with_size(width: i32, height: i32) -> Self {
        Self {
            captcha_instance: T::with_size(width, height),
        }
    }

    fn with_size_and_len(width: i32, height: i32, len: usize) -> Self {
        Self {
            captcha_instance: T::with_size_and_len(width, height, len),
        }
    }

    fn with_all(width: i32, height: i32, len: usize, font: CaptchaFont, font_size: f32) -> Self {
        Self {
            captcha_instance: T::with_all(width, height, len, font, font_size),
        }
    }
}
