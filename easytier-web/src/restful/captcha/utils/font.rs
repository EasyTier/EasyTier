use font_kit::font::Font;
use rust_embed::RustEmbed;
use std::error::Error;
use std::sync::Arc;

#[derive(RustEmbed)]
#[folder = "resources/"]
struct FontAssets;

// lazy_static! {
//     pub(crate) static ref FONTS: RwLock<HashMap<String, Arc<Font>>> = Default::default();
// }

pub fn get_font(font_name: &str) -> Option<Arc<Font>> {
    // let fonts_cell = FONTS.get_or_init(|| Default::default());
    // let guard = fonts_cell.read();
    //
    // if guard.contains_key(font_name) {
    //     Some(guard.get(font_name).unwrap().clone())
    // } else {
    //     drop(guard);

    if let Ok(Some(font)) = load_font(font_name) {
        // let mut guard = fonts_cell.write();
        let font = Arc::new(font);
        // guard.insert(String::from(font_name), font.clone());
        Some(font)
    } else {
        None
    }
    // }
}

pub fn load_font(font_name: &str) -> Result<Option<Font>, Box<dyn Error>> {
    match FontAssets::get(font_name) {
        Some(assets) => {
            let font = Font::from_bytes(Arc::new(Vec::from(assets.data)), 0)?;
            Ok(Some(font))
        }
        None => {
            tracing::error!("Unable to find the specified font.");
            Ok(None)
        }
    }
}
