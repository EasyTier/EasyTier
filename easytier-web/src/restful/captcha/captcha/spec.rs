//! Static alphabetical PNG Captcha
//!
//! PNG格式验证码
//!

use super::super::base::captcha::{AbstractCaptcha, Captcha};

use super::super::utils::png::WritePng;
use super::super::{CaptchaFont, NewCaptcha};
use font_kit::canvas::RasterizationOptions;

use font_kit::hinting::HintingOptions;
use raqote::{DrawOptions, DrawTarget, Point, SolidSource, Source};
use std::io::Write;

/// PNG格式验证码
pub struct SpecCaptcha {
    pub(crate) captcha: Captcha,
}

impl SpecCaptcha {
    /// 生成验证码图形
    pub(crate) fn graphics_image(
        &mut self,
        str: &Vec<char>,
        out: impl Write,
    ) -> Result<(), png::EncodingError> {
        let width = self.captcha.width;
        let height = self.captcha.height;

        let mut dt = DrawTarget::new(width, height);

        // 填充背景
        dt.fill_rect(
            0.,
            0.,
            width as f32,
            height as f32,
            &Source::Solid(SolidSource::from(raqote::Color::new(255, 255, 255, 255))),
            &DrawOptions::new(),
        );

        // 画干扰圆
        self.captcha.draw_oval(0, &mut dt, None);

        // 画干扰线
        self.captcha.draw_bessel_line(0, &mut dt, None);

        // 画字符串
        let font = self.captcha.get_font();
        let font_size = self.captcha.get_font_size();
        let glyph = font.glyph_for_char('W').unwrap();
        let bounds = font
            .raster_bounds(
                glyph,
                font_size,
                Default::default(),
                HintingOptions::None,
                RasterizationOptions::GrayscaleAa,
            )
            .unwrap();

        let f_w = width / str.len() as i32; // 每个字符所占宽度
        let f_sp = (f_w - bounds.width()) / 2; // 字符的左右边距
        for (i, ch) in str.iter().enumerate() {
            let color: raqote::Color = self.captcha.color().into();
            let glyph = font.glyph_for_char(ch.clone());
            if glyph.is_none() {
                continue;
            }

            let bounds = font
                .raster_bounds(
                    glyph.unwrap(),
                    font_size,
                    Default::default(),
                    HintingOptions::None,
                    RasterizationOptions::GrayscaleAa,
                )
                .unwrap();

            let f_y = height - ((height - bounds.height() as i32) >> 1);

            dt.draw_glyphs(
                &font,
                font_size,
                &[glyph.unwrap()],
                &[Point::new(
                    (i as i32 * f_w + f_sp + 3) as f32,
                    f_y as f32 - 3.,
                )],
                &Source::Solid(SolidSource::from(color)),
                &DrawOptions::new(),
            )
        }

        dt.write_png(out)
    }
}

impl NewCaptcha for SpecCaptcha {
    fn new() -> Self {
        Self {
            captcha: Captcha::new(),
        }
    }

    fn with_size(width: i32, height: i32) -> Self {
        Self {
            captcha: Captcha::with_size(width, height),
        }
    }

    fn with_size_and_len(width: i32, height: i32, len: usize) -> Self {
        Self {
            captcha: Captcha::with_size_and_len(width, height, len),
        }
    }

    fn with_all(width: i32, height: i32, len: usize, font: CaptchaFont, font_size: f32) -> Self {
        Self {
            captcha: Captcha::with_all(width, height, len, font, font_size),
        }
    }
}

impl AbstractCaptcha for SpecCaptcha {
    type Error = png::EncodingError;

    fn out(&mut self, out: impl Write) -> Result<(), Self::Error> {
        let text_char = self.captcha.text_char();
        self.graphics_image(&text_char, out)
    }

    fn get_chars(&mut self) -> Vec<char> {
        self.captcha.text_char()
    }

    fn base64(&mut self) -> Result<String, Self::Error> {
        self.base64_with_head("data:image/png;base64,")
    }

    fn get_content_type(&mut self) -> String {
        "image/png".into()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn it_works() {}
}
