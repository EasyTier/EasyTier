pub(crate) use crate::common::dns::resolver_config as resolver_conf;
use hickory_proto::rr::LowerName;
use idna::AsciiDenyList;

pub fn sanitize(name: impl AsRef<str>) -> String {
    let name = name.as_ref();
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

pub fn parse(name: impl AsRef<str>) -> LowerName {
    let name = name.as_ref();
    if let Ok(name) = name.parse() {
        name
    } else {
        let sanitized = sanitize(name);
        tracing::debug!("invalid name: {}, sanitized to: {}", name, sanitized);
        sanitized.parse().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matrix_cases() {
        let cases = [
            ["Example.COM.", "example.com."],
            ["a_b!.et.net.", "a-b.et.net."],
            ["foo..bar.com.", "foo.bar.com."],
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.",
            ],
            ["___", "___"],
            ["!", ""],
            ["", ""],
        ];

        for [input, expected] in cases {
            let parsed = parse(input);
            let expected: LowerName = expected.parse().unwrap();
            assert_eq!(
                parsed, expected,
                "parse({input:?}) should equal {expected:?}, got {parsed:?}"
            );
        }
    }
}
