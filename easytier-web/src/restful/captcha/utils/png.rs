//! 处理PNG的编码和转换

use png::EncodingError;
use raqote::DrawTarget;
use std::io::Write;

pub(crate) trait WritePng {
    fn write_png(&self, w: impl Write) -> Result<(), png::EncodingError>;
}

impl WritePng for DrawTarget {
    fn write_png(&self, w: impl Write) -> Result<(), EncodingError> {
        let mut encoder = png::Encoder::new(w, self.width() as u32, self.height() as u32);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        let buf = self.get_data();
        let mut output = Vec::with_capacity(buf.len() * 4);

        for pixel in buf {
            let a = (pixel >> 24) & 0xffu32;
            let mut r = (pixel >> 16) & 0xffu32;
            let mut g = (pixel >> 8) & 0xffu32;
            let mut b = (pixel >> 0) & 0xffu32;

            if a > 0u32 {
                r = r * 255u32 / a;
                g = g * 255u32 / a;
                b = b * 255u32 / a;
            }

            output.push(r as u8);
            output.push(g as u8);
            output.push(b as u8);
            output.push(a as u8);
        }

        writer.write_image_data(&output)
    }
}
