//! Rust图形验证码，由Java同名开源库[whvcse/EasyCaptcha](https://github.com/ele-admin/EasyCaptcha)移植而来👏，100%纯Rust实现，支持gif、算术等类型。
//!
//! Rust Captcha library, which is ported from Java's same-name library [whvcse/EasyCaptcha](https://github.com/ele-admin/EasyCaptcha),
//! implemented in 100% pure Rust, supporting GIF and arithmetic problems.
//!
//! <br/>
//!
//! 目前已适配框架 / Frameworks which is adapted now:
//!
//!  - `axum` + 内存 challenge store
//!
//!  更多框架欢迎您提交PR，参与适配🙏 PR for new frameworks are welcomed
//!
//! <br/>
//!
//! ## 安装 Install
//!
//! 请参考Github README为Linux系统安装依赖。
//!
//! If you are compiling this project in linux, please refer to README in repository to install
//! dependencies into you system.
//!
//! ## 使用 Usage
//!
//! 若您正在使用的框架已适配，您可直接通过[CaptchaUtil](extension::CaptchaUtil)类（并导入相应框架的trait）来使用验证码：
//!
//! If your framework is adapted, you can just use [CaptchaUtil](extension::CaptchaUtil) and importing traits of your
//! framework to use the Captcha:
//!
//! ```
//! use std::collections::HashMap;
//! use axum::extract::Query;
//! use axum::response::IntoResponse;
//! use easy_captcha::captcha::gif::GifCaptcha;
//! use easy_captcha::extension::axum_tower_sessions::CaptchaAxumChallengeStoreExt;
//! use easy_captcha::extension::CaptchaUtil;
//! use easy_captcha::NewCaptcha;
//! use crate::restful::auth_state::CaptchaChallengeStore;
//!
//! /// 接口：获取验证码
//! /// Handler: Get a captcha
//! async fn get_captcha(challenge_store: CaptchaChallengeStore) -> Result<axum::response::Response, axum::http::StatusCode> {
//!     let mut captcha: CaptchaUtil<GifCaptcha> = CaptchaUtil::new();
//!     match captcha.out_with_challenge_store(&challenge_store).await {
//!         Ok(response) => Ok(response),
//!         Err(_) => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
//!     }
//! }
//!
//! // 验证时请在业务层从 challenge store 读取并消费 challenge_id。
//! ```
//!
//! 您也可以自定义验证码的各项属性
//!
//! You can also specify properties of the Captcha.
//!
//! ```rust
//! use easy_captcha::captcha::gif::GifCaptcha;
//! use easy_captcha::extension::axum_tower_sessions::CaptchaAxumChallengeStoreExt;
//! use easy_captcha::extension::CaptchaUtil;
//! use easy_captcha::NewCaptcha;
//! use crate::restful::auth_state::CaptchaChallengeStore;
//!
//! async fn get_captcha(challenge_store: CaptchaChallengeStore) -> Result<axum::response::Response, axum::http::StatusCode> {
//!     let mut captcha: CaptchaUtil<GifCaptcha> = CaptchaUtil::with_size_and_len(127, 48, 4);
//!     match captcha.out_with_challenge_store(&challenge_store).await {
//!         Ok(response) => Ok(response),
//!         Err(_) => Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR),
//!     }
//! }
//! ```
//!
//! 项目当前提供了三种验证码实现：[SpecCaptcha](captcha::spec::SpecCaptcha)（静态PNG）、[GifCaptcha](captcha::gif::GifCaptcha)（动态GIF）
//! 、[ArithmeticCaptcha](captcha::arithmetic::ArithmeticCaptcha)（算术PNG），您可按需使用。
//!
//! There is three implementation of Captcha currently, which are [SpecCaptcha](captcha::spec::SpecCaptcha)(static PNG),
//! [GifCaptcha](captcha::gif::GifCaptcha)(GIF), [ArithmeticCaptcha](captcha::arithmetic::ArithmeticCaptcha)(Arithmetic problems),
//! you can use them according to your need.
//!
//! <br/>
//!
//! 自带字体效果 / Fonts shipped
//!
//! | 字体/Fonts            | 效果/Preview                                     |
//! |---------------------|------------------------------------------------|
//! | CaptchaFont::Font1  | ![](https://s2.ax1x.com/2019/08/23/msMe6U.png) |
//! | CaptchaFont::Font2  | ![](https://s2.ax1x.com/2019/08/23/msMAf0.png) |
//! | CaptchaFont::Font3  | ![](https://s2.ax1x.com/2019/08/23/msMCwj.png) |
//! | CaptchaFont::Font4  | ![](https://s2.ax1x.com/2019/08/23/msM9mQ.png) |
//! | CaptchaFont::Font5  | ![](https://s2.ax1x.com/2019/08/23/msKz6S.png) |
//! | CaptchaFont::Font6  | ![](https://s2.ax1x.com/2019/08/23/msKxl8.png) |
//! | CaptchaFont::Font7  | ![](https://s2.ax1x.com/2019/08/23/msMPTs.png) |
//! | CaptchaFont::Font8  | ![](https://s2.ax1x.com/2019/08/23/msMmXF.png) |
//! | CaptchaFont::Font9  | ![](https://s2.ax1x.com/2019/08/23/msMVpV.png) |
//! | CaptchaFont::Font10 | ![](https://s2.ax1x.com/2019/08/23/msMZlT.png) |
//!

#![warn(missing_docs)]
#![allow(dead_code)]

pub(crate) mod base;
pub mod builder;
pub mod extension;
mod utils;

pub use base::captcha::*;

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn it_works() {
//
//     }
// }
