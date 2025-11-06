use super::super::base::randoms::Randoms;

use super::super::utils::color::Color;
use super::super::utils::font;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

use rusttype::Font;
use std::fmt::Debug;
use std::io::Write;
use std::sync::Arc;

/// 验证码抽象类
pub(crate) struct Captcha {
    /// 随机数工具类
    pub(crate) randoms: Randoms,

    /// 常用颜色
    color: Vec<Color>,

    /// 字体名称
    font_names: [&'static str; 1],

    /// 验证码的字体
    font_name: String,

    /// 验证码的字体大小
    font_size: f32,

    /// 验证码随机字符长度
    pub len: usize,

    /// 验证码显示宽度
    pub width: i32,

    /// 验证码显示高度
    pub height: i32,

    /// 验证码类型
    char_type: CaptchaType,

    /// 当前验证码
    pub(crate) chars: Option<String>,
}

/// 验证码文本类型 The character type of the captcha
pub enum CaptchaType {
    /// 字母数字混合
    Default = 1,

    /// 纯数字
    OnlyNumber,

    /// 纯字母
    OnlyChar,

    /// 纯大写字母
    OnlyUpper,

    /// 纯小写字母
    OnlyLower,

    /// 数字大写字母
    NumAndUpper,
}

/// 内置字体 Fonts shipped with the library
pub enum CaptchaFont {
    /// actionj
    Font1,
    /// epilog
    Font2,
    /// fresnel
    Font3,
    /// headache
    Font4,
    /// lexo
    Font5,
    /// prefix
    Font6,
    /// progbot
    Font7,
    /// ransom
    Font8,
    /// robot
    Font9,
    /// scandal
    Font10,
}

impl Captcha {
    /// 生成随机验证码
    pub fn alphas(&mut self) -> Vec<char> {
        let mut cs = vec!['\0'; self.len];
        for cs_i in cs.iter_mut() {
            match self.char_type {
                CaptchaType::Default => *cs_i = self.randoms.alpha(),
                CaptchaType::OnlyNumber => {
                    *cs_i = self.randoms.alpha_under(self.randoms.num_max_index)
                }
                CaptchaType::OnlyChar => {
                    *cs_i = self
                        .randoms
                        .alpha_between(self.randoms.char_min_index, self.randoms.char_max_index)
                }
                CaptchaType::OnlyUpper => {
                    *cs_i = self
                        .randoms
                        .alpha_between(self.randoms.upper_min_index, self.randoms.upper_max_index)
                }
                CaptchaType::OnlyLower => {
                    *cs_i = self
                        .randoms
                        .alpha_between(self.randoms.lower_min_index, self.randoms.lower_max_index)
                }
                CaptchaType::NumAndUpper => {
                    *cs_i = self.randoms.alpha_under(self.randoms.upper_max_index)
                }
            }
        }

        self.chars = Some(cs.iter().collect());
        cs
    }

    /// 获取当前的验证码
    pub fn text(&mut self) -> String {
        self.check_alpha();
        self.chars.clone().unwrap()
    }

    /// 获取当前验证码的字符数组
    pub fn text_char(&mut self) -> Vec<char> {
        self.check_alpha();
        self.chars.clone().unwrap().chars().collect()
    }

    /// 检查验证码是否生成，没有则立即生成
    pub fn check_alpha(&mut self) {
        if self.chars.is_none() {
            self.alphas();
        }
    }

    pub fn get_font(&'_ mut self) -> Arc<Font<'_>> {
        if let Some(font) = font::get_font(&self.font_name) {
            font
        } else {
            font::get_font(self.font_names[0]).unwrap()
        }
    }

    pub fn get_font_size(&mut self) -> f32 {
        self.font_size
    }

    pub fn set_font_by_enum(&mut self, font: CaptchaFont, size: Option<f32>) {
        let font_name = self.font_names[font as usize];
        self.font_name = font_name.into();
        self.font_size = size.unwrap_or(32.);
    }
}

/// 初始化验证码的抽象方法 Traits for initialize a Captcha instance.
pub trait NewCaptcha
where
    Self: Sized,
{
    /// 用默认参数初始化
    ///
    /// Initialize the Captcha with the default properties.
    fn new() -> Self;

    /// 使用输出图像大小初始化
    ///
    /// Initialize the Captcha with the size of output image.
    fn with_size(width: i32, height: i32) -> Self;

    /// 使用输出图像大小和验证码字符长度初始化
    ///
    /// Initialize the Captcha with the size of output image and the character length of the Captcha.
    ///
    /// <br/>
    ///
    /// 特别地/In particular:
    ///
    /// - 对算术验证码[ArithmeticCaptcha](crate::captcha::arithmetic::ArithmeticCaptcha)而言，这里的`len`是验证码中数字的数量。
    ///
    /// For [ArithmeticCaptcha](crate::captcha::arithmetic::ArithmeticCaptcha), the `len` presents the count of the digits
    /// in the Captcha.
    fn with_size_and_len(width: i32, height: i32, len: usize) -> Self;

    /// 使用完整的参数来初始化，包括输出图像大小、验证码字符长度和输出字体及其大小
    ///
    /// Initialize the Captcha with full properties, including the size of output image, the character length of the Captcha,
    /// and the font used in Captcha with the font size.
    ///
    /// 关于`len`字段的注意事项，请参见[with_size_and_len](Self::with_size_and_len)中的说明。Refer to the document of
    /// [with_size_and_len](Self::with_size_and_len) for the precautions of the `len` property.
    fn with_all(width: i32, height: i32, len: usize, font: CaptchaFont, font_size: f32) -> Self;
}

impl NewCaptcha for Captcha {
    fn new() -> Self {
        let color = [
            (0, 135, 255),
            (51, 153, 51),
            (255, 102, 102),
            (255, 153, 0),
            (153, 102, 0),
            (153, 102, 153),
            (51, 153, 153),
            (102, 102, 255),
            (0, 102, 204),
            (204, 51, 51),
            (0, 153, 204),
            (0, 51, 102),
        ]
        .iter()
        .map(|v| (*v).into())
        .collect();

        let font_names = ["robot.ttf"];

        let font_name = font_names[0].into();
        let font_size = 32.;
        let len = 5;
        let width = 130;
        let height = 48;
        let char_type = CaptchaType::Default;
        let chars = None;

        Self {
            randoms: Randoms::new(),
            color,
            font_names,
            font_name,
            font_size,
            len,
            width,
            height,
            char_type,
            chars,
        }
    }

    fn with_size(width: i32, height: i32) -> Self {
        let mut _self = Self::new();
        _self.width = width;
        _self.height = height;
        _self
    }

    fn with_size_and_len(width: i32, height: i32, len: usize) -> Self {
        let mut _self = Self::new();
        _self.width = width;
        _self.height = height;
        _self.len = len;
        _self
    }

    fn with_all(width: i32, height: i32, len: usize, font: CaptchaFont, font_size: f32) -> Self {
        let mut _self = Self::new();
        _self.width = width;
        _self.height = height;
        _self.len = len;
        _self.set_font_by_enum(font, None);
        _self.font_size = font_size;
        _self
    }
}

/// 验证码的抽象方法  Traits which a Captcha must implements.
pub trait AbstractCaptcha: NewCaptcha {
    /// 错误类型
    type Error: std::error::Error + Debug + Send + Sync + 'static;

    /// 输出验证码到指定位置
    ///
    /// Write the Captcha image to the specified place.
    fn out(&mut self, out: impl Write) -> Result<(), Self::Error>;

    /// 获取验证码中的字符（即正确答案）
    ///
    /// Get the characters (i.e. the correct answer) of the Captcha
    fn get_chars(&mut self) -> Vec<char>;

    /// 输出Base64编码。注意，返回值会带编码头（例如`data:image/png;base64,`），可以直接在浏览器中显示；如不需要编码头，
    /// 请使用[base64_with_head](Self::base64_with_head)方法并传入空参数以去除编码头。
    ///
    /// Get the Base64 encoded image. Reminds: the returned Base64 strings will begin with an encoding head like
    /// `data:image/png;base64,`, which make it possible to display in browsers directly. If you don't need it, you may
    /// use [base64_with_head](Self::base64_with_head) and pass a null string.
    fn base64(&mut self) -> Result<String, Self::Error>;

    /// 获取验证码的MIME类型
    ///
    /// Get the MIME Content type of the Captcha.
    fn get_content_type(&mut self) -> String;

    /// 输出Base64编码（指定编码头）
    ///
    /// Get the Base64 encoded image, with specified encoding head.
    fn base64_with_head(&mut self, head: &str) -> Result<String, Self::Error> {
        let mut output_stream = Vec::new();
        self.out(&mut output_stream)?;
        Ok(String::from(head) + &BASE64_STANDARD.encode(&output_stream))
    }
}
