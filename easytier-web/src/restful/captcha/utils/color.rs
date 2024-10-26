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

impl Into<(u8, u8, u8, u8)> for Color {
    fn into(self) -> (u8, u8, u8, u8) {
        (
            (self.0 * 255.0) as u8,
            (self.1 * 255.0) as u8,
            (self.2 * 255.0) as u8,
            (self.3 * 255.0) as u8,
        )
    }
}

impl Into<u32> for Color {
    fn into(self) -> u32 {
        let color: (u8, u8, u8, u8) = self.into();
        (color.0 as u32) << 24 + (color.1 as u32) << 16 + (color.2 as u32) << 8 + (color.3 as u32)
    }
}

impl Into<raqote::Color> for Color {
    fn into(self) -> raqote::Color {
        let color: (u8, u8, u8, u8) = self.into();
        raqote::Color::new(color.3, color.0, color.1, color.2)
    }
}

impl Color {}
