use hickory_proto::rr::LowerName;
use idna::AsciiDenyList;

pub mod addr;
pub mod dirty;
pub mod response;
pub mod zone_handler;

pub fn sanitize(name: &str) -> String {
    let dot = name.ends_with('.');
    let mut name = idna::domain_to_ascii_cow(name.as_ref(), AsciiDenyList::EMPTY)
        .unwrap_or_default()
        .into_owned()
        .to_lowercase()
        .split('.')
        .map(|label| {
            label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(63)
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    name.truncate(253);
    if dot {
        name.push('.');
    }
    name
}

pub fn parse(name: &str) -> LowerName {
    if let Ok(name) = name.parse() {
        name
    } else {
        let sanitized = sanitize(name);
        tracing::debug!("invalid hostname: {}, sanitized to: {}", name, sanitized);
        sanitized.parse().unwrap_or_default()
    }
}
