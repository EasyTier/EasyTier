//! RGBA颜色
use std::fmt::{Debug, Formatter};

#[derive(Clone)]
pub struct Color(f64, f64, f64, f64);

impl Color {
    pub fn set_alpha(&mut self, a: f64) {
        self.3 = a;
    }
}

impl Debug for Color {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Color")
            .field("r", &self.0)
            .field("g", &self.1)
            .field("b", &self.2)
            .field("a", &self.3)
            .finish()
    }
}

impl From<(u8, u8, u8)> for Color {
    fn from(value: (u8, u8, u8)) -> Self {
        Self(
            value.0 as f64 / 255.0,
            value.1 as f64 / 255.0,
            value.2 as f64 / 255.0,
            1.0,
        )
    }
}

impl From<Color> for (u8, u8, u8, u8) {
    fn from(val: Color) -> Self {
        (
            (val.0 * 255.0) as u8,
            (val.1 * 255.0) as u8,
            (val.2 * 255.0) as u8,
            (val.3 * 255.0) as u8,
        )
    }
}

impl From<Color> for u32 {
    fn from(val: Color) -> Self {
        let color: (u8, u8, u8, u8) = val.into();
        (color.0 as u32)
            << (24 + (color.1 as u32))
            << (16 + (color.2 as u32))
            << (8 + (color.3 as u32))
    }
}

impl Color {}
