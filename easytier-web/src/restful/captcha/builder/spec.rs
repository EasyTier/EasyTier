//! Static alphabetical PNG Captcha
//!
//! PNG格式验证码
//!

use super::super::base::captcha::{AbstractCaptcha, Captcha};

use super::super::{CaptchaFont, NewCaptcha};

use image::{ImageBuffer, Rgba};
use imageproc::drawing;
use rand::{rngs::ThreadRng, Rng};
use rusttype::{Font, Scale};
use std::io::{Cursor, Write};
use std::sync::Arc;

mod color {
    use image::Rgba;
    use rand::{rngs::ThreadRng, Rng};
    pub fn gen_background_color(rng: &mut ThreadRng) -> Rgba<u8> {
        let red = rng.gen_range(200..=255);
        let green = rng.gen_range(200..=255);
        let blue = rng.gen_range(200..=255);
        //let a=rng.gen_range(0..255);
        Rgba([red, green, blue, 255])
    }
    pub fn gen_text_color(rng: &mut ThreadRng) -> Rgba<u8> {
        let red = rng.gen_range(0..=150);
        let green = rng.gen_range(0..=150);
        let blue = rng.gen_range(0..=150);
        Rgba([red, green, blue, 255])
    }

    pub fn gen_line_color(rng: &mut ThreadRng) -> Rgba<u8> {
        let red = rng.gen_range(100..=255);
        let green = rng.gen_range(100..=255);
        let blue = rng.gen_range(100..=255);
        Rgba([red, green, blue, 255])
    }
}

///the builder of captcha
pub struct CaptchaBuilder<'a, 'b> {
    ///captcha image width
    pub width: u32,
    ///captcha image height
    pub height: u32,

    ///random string length.
    pub length: u32,

    ///source is a unicode which is the rand string from.
    pub source: String,

    ///image background color (optional)
    pub background_color: Option<Rgba<u8>>,
    ///fonts collection for text
    pub fonts: &'b [Arc<Font<'a>>],
    ///The maximum number of lines to draw behind of the image
    pub max_behind_lines: Option<u32>,
    ///The maximum number of lines to draw in front of the image
    pub max_front_lines: Option<u32>,
    ///The maximum number of ellipse lines to draw in front of the image
    pub max_ellipse_lines: Option<u32>,
}

impl<'a, 'b> Default for CaptchaBuilder<'a, 'b> {
    fn default() -> Self {
        Self {
            width: 150,
            height: 40,
            length: 5,
            source: String::from("1234567890qwertyuioplkjhgfdsazxcvbnm"),
            background_color: None,
            fonts: &[],
            max_behind_lines: None,
            max_front_lines: None,
            max_ellipse_lines: None,
        }
    }
}

impl<'a, 'b> CaptchaBuilder<'a, 'b> {
    fn write_phrase(
        &self,
        image: &mut ImageBuffer<Rgba<u8>, Vec<u8>>,
        rng: &mut ThreadRng,
        phrase: &str,
    ) {
        //println!("phrase={}", phrase);
        //println!("width={}, height={}", self.width, self.height);
        let font_size = (self.width as f32) / (self.length as f32) - rng.gen_range(1.0..=4.0);
        let scale = Scale::uniform(font_size);
        if self.fonts.is_empty() {
            panic!("no fonts loaded");
        }
        let font_index = rng.gen_range(0..self.fonts.len());
        let font = &self.fonts[font_index];
        let glyphs: Vec<_> = font
            .layout(phrase, scale, rusttype::point(0.0, 0.0))
            .collect();
        let text_height = {
            let v_metrics = font.v_metrics(scale);
            (v_metrics.ascent - v_metrics.descent).ceil() as u32
        };
        let text_width = {
            let min_x = glyphs.first().unwrap().pixel_bounding_box().unwrap().min.x;
            let max_x = glyphs.last().unwrap().pixel_bounding_box().unwrap().max.x;
            let last_x_pos = glyphs.last().unwrap().position().x as i32;
            (max_x + last_x_pos - min_x) as u32
        };
        let node_width = text_width / self.length;
        //println!("text_width={}, text_height={}", text_width, text_height);
        let mut x = ((self.width as i32) - (text_width as i32)) / 2;
        let y = ((self.height as i32) - (text_height as i32)) / 2;
        //
        for s in phrase.chars() {
            let text_color = color::gen_text_color(rng);
            let offset = rng.gen_range(-5..=5);
            //println!("x={}, y={}", x, y);
            drawing::draw_text_mut(
                image,
                text_color,
                x,
                y + offset,
                scale,
                font,
                &s.to_string(),
            );
            x += node_width as i32;
        }
    }

    fn draw_line(&self, image: &mut ImageBuffer<Rgba<u8>, Vec<u8>>, rng: &mut ThreadRng) {
        let line_color = color::gen_line_color(rng);
        let is_h = rng.gen();
        let (start, end) = if is_h {
            let xa = rng.gen_range(0.0..(self.width as f32) / 2.0);
            let ya = rng.gen_range(0.0..(self.height as f32));
            let xb = rng.gen_range((self.width as f32) / 2.0..(self.width as f32));
            let yb = rng.gen_range(0.0..(self.height as f32));
            ((xa, ya), (xb, yb))
        } else {
            let xa = rng.gen_range(0.0..(self.width as f32));
            let ya = rng.gen_range(0.0..(self.height as f32) / 2.0);
            let xb = rng.gen_range(0.0..(self.width as f32));
            let yb = rng.gen_range((self.height as f32) / 2.0..(self.height as f32));
            ((xa, ya), (xb, yb))
        };
        let thickness = rng.gen_range(2..4);
        for i in 0..thickness {
            let offset = i as f32;
            if is_h {
                drawing::draw_line_segment_mut(
                    image,
                    (start.0, start.1 + offset),
                    (end.0, end.1 + offset),
                    line_color,
                );
            } else {
                drawing::draw_line_segment_mut(
                    image,
                    (start.0 + offset, start.1),
                    (end.0 + offset, end.1),
                    line_color,
                );
            }
        }
    }

    fn draw_ellipse(&self, image: &mut ImageBuffer<Rgba<u8>, Vec<u8>>, rng: &mut ThreadRng) {
        let line_color = color::gen_line_color(rng);
        let thickness = rng.gen_range(2..4);
        for i in 0..thickness {
            let center = (
                rng.gen_range(-(self.width as i32) / 4..(self.width as i32) * 5 / 4),
                rng.gen_range(-(self.height as i32) / 4..(self.height as i32) * 5 / 4),
            );
            drawing::draw_hollow_ellipse_mut(
                image,
                (center.0, center.1 + i),
                (self.width * 6 / 7) as i32,
                (self.height * 5 / 8) as i32,
                line_color,
            );
        }
    }

    fn build_image(&self, phrase: String) -> ImageBuffer<Rgba<u8>, Vec<u8>> {
        let mut rng = rand::thread_rng();
        let bgc = match self.background_color {
            Some(v) => v,
            None => color::gen_background_color(&mut rng),
        };
        let mut image = ImageBuffer::from_fn(self.width, self.height, |_, _| bgc);
        //draw behind line
        let square = self.width * self.height;
        let effects = match self.max_behind_lines {
            Some(s) => {
                if s > 0 {
                    rng.gen_range(square / 3000..square / 2000).min(s)
                } else {
                    0
                }
            }
            None => rng.gen_range(square / 3000..square / 2000),
        };
        for _ in 0..effects {
            self.draw_line(&mut image, &mut rng);
        }
        //write phrase
        self.write_phrase(&mut image, &mut rng, &phrase);
        //draw front line
        let effects = match self.max_front_lines {
            Some(s) => {
                if s > 0 {
                    rng.gen_range(square / 3000..=square / 2000).min(s)
                } else {
                    0
                }
            }
            None => rng.gen_range(square / 3000..=square / 2000),
        };
        for _ in 0..effects {
            self.draw_line(&mut image, &mut rng);
        }
        //draw ellipse
        let effects = match self.max_front_lines {
            Some(s) => {
                if s > 0 {
                    rng.gen_range(square / 4000..=square / 3000).min(s)
                } else {
                    0
                }
            }
            None => rng.gen_range(square / 4000..=square / 3000),
        };
        for _ in 0..effects {
            self.draw_ellipse(&mut image, &mut rng);
        }

        image
    }
}

/// PNG格式验证码
pub struct SpecCaptcha {
    pub(crate) captcha: Captcha,
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
    type Error = image::ImageError;

    fn out(&mut self, mut out: impl Write) -> Result<(), Self::Error> {
        let phrase = self.captcha.text_char();
        let builder = CaptchaBuilder {
            width: self.captcha.width as u32,
            height: self.captcha.height as u32,
            length: self.captcha.len as u32,
            background_color: None,
            fonts: &[self.captcha.get_font()],
            max_behind_lines: Some(0),
            max_front_lines: Some(0),
            max_ellipse_lines: Some(0),
            ..Default::default()
        };
        let image = builder.build_image(phrase.iter().collect());
        let format = image::ImageOutputFormat::Png;
        let mut raw_data: Vec<u8> = Vec::new();
        image.write_to(&mut Cursor::new(&mut raw_data), format)?;
        out.write_all(&raw_data)?;
        Ok(())
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
