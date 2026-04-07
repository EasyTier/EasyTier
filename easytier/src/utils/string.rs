pub fn cost_to_str(cost: i32) -> String {
    if cost == 1 {
        "p2p".to_string()
    } else {
        format!("relay({})", cost)
    }
}

pub fn float_to_str(f: f64, precision: usize) -> String {
    format!("{:.1$}", f, precision)
}

#[cfg(target_os = "windows")]
pub fn utf8_or_gbk_to_string(s: &[u8]) -> String {
    use encoding::{DecoderTrap, Encoding, all::GBK};
    if let Ok(utf8_str) = String::from_utf8(s.to_vec()) {
        utf8_str
    } else {
        // 如果解码失败，则尝试使用GBK解码
        if let Ok(gbk_str) = GBK.decode(s, DecoderTrap::Strict) {
            gbk_str
        } else {
            String::from_utf8_lossy(s).to_string()
        }
    }
}
