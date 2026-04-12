//! - Axum: [axum](https://docs.rs/axum)

use super::AbstractCaptcha;
use super::CaptchaUtil;
use async_trait::async_trait;
use axum::response::Response;
use std::fmt::Debug;
use uuid::Uuid;

use crate::restful::auth_state::CaptchaChallengeStore;
pub const CAPTCHA_ID_HEADER: &str = "X-Captcha-Id";

#[async_trait]
pub trait CaptchaAxumChallengeStoreExt {
    type Error: Debug + Send + Sync + 'static;

    async fn out_with_challenge_store(
        &mut self,
        challenge_store: &CaptchaChallengeStore,
    ) -> Result<Response, Self::Error>;
}

#[async_trait]
impl<T: AbstractCaptcha + Send> CaptchaAxumChallengeStoreExt for CaptchaUtil<T> {
    type Error = anyhow::Error;

    async fn out_with_challenge_store(
        &mut self,
        challenge_store: &CaptchaChallengeStore,
    ) -> Result<Response, Self::Error> {
        let mut data = vec![];
        self.captcha_instance.out(&mut data)?;

        let answer: String = self.captcha_instance.get_chars().iter().collect();
        let challenge_id = Uuid::new_v4().simple().to_string();
        challenge_store.insert(challenge_id.clone(), answer);

        let resp = Response::builder()
            .header("Content-Type", self.captcha_instance.get_content_type())
            .header(CAPTCHA_ID_HEADER, &challenge_id)
            .body(data.into())?;
        Ok(resp)
    }
}
