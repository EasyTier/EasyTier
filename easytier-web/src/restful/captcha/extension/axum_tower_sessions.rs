//! Axum & Tower_sessions 组合
//!
//! - Axum: [axum](https://docs.rs/axum)
//! - Tower Sessions: [axum](https://docs.rs/tower-sessions)

use super::AbstractCaptcha;
use super::CaptchaUtil;
use async_trait::async_trait;
use axum::response::Response;
use std::fmt::Debug;
use tower_sessions::Session;

const CAPTCHA_KEY: &'static str = "ez-captcha";

/// Axum & Tower_Sessions
#[async_trait]
pub trait CaptchaAxumTowerSessionExt {
    /// 错误类型
    type Error: Debug + Send + Sync + 'static;

    /// 将验证码图片写入响应，并将用户的验证码信息保存至Session中
    ///
    /// Write the Captcha Image into the response and save the Captcha information into the user's Session.
    async fn out(&mut self, session: &Session) -> Result<Response, Self::Error>;
}

/// Axum & Tower_Sessions - 静态方法
#[async_trait]
pub trait CaptchaAxumTowerSessionStaticExt {
    /// 验证验证码，返回的布尔值代表验证码是否正确
    ///
    /// Verify the Captcha code, and return whether user's code is correct.
    async fn ver(code: &str, session: &Session) -> bool {
        match session.get::<String>(CAPTCHA_KEY).await {
            Ok(Some(ans)) => ans.to_ascii_lowercase() == code.to_ascii_lowercase(),
            _ => false,
        }
    }

    /// 清除Session中的验证码
    ///
    /// Clear the Captcha in the session.
    async fn clear(session: &Session) {
        if session.remove::<String>(CAPTCHA_KEY).await.is_err() {
            tracing::warn!("Exception occurs during clearing the session.")
        }
    }
}

#[async_trait]
impl<T: AbstractCaptcha + Send> CaptchaAxumTowerSessionExt for CaptchaUtil<T> {
    type Error = anyhow::Error;

    async fn out(&mut self, session: &Session) -> Result<Response, Self::Error> {
        let mut data = vec![];
        self.captcha_instance.out(&mut data)?;

        let ans: String = self.captcha_instance.get_chars().iter().collect();
        session.insert(CAPTCHA_KEY, ans).await?;

        let resp = Response::builder()
            .header("Content-Type", self.captcha_instance.get_content_type())
            .body(data.into())?;
        Ok(resp)
    }
}

#[async_trait]
impl CaptchaAxumTowerSessionStaticExt for CaptchaUtil {}
