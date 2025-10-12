use idna::domain_to_ascii;
pub fn convert_idn_to_ascii(url_str: &str) -> Result<String, String> {
    if url_str.chars().any(|c| !c.is_ascii()) {
        let mut url_parts = url_str.splitn(2, "://");
        let scheme = url_parts.next().unwrap_or("");
        let rest = url_parts.next().unwrap_or(url_str);
        let (host_part, port_part, path_part) = {
            let mut path_and_rest = rest.splitn(2, '/');
            let host_port_part = path_and_rest.next().unwrap_or("");
            let path_part = path_and_rest.next().map(|s| format!("/{}", s)).unwrap_or_default();
            if host_port_part.starts_with('[') {
                if let Some(end_bracket_pos) = host_port_part.find(']') {
                    let host_part = &host_port_part[..end_bracket_pos + 1];
                    let remaining = &host_port_part[end_bracket_pos + 1..];
                    if remaining.starts_with(':') {
                        let port_str = &remaining[1..];
                        if port_str.chars().all(|c| c.is_ascii_digit()) {
                            (host_part, format!(":{}", port_str), path_part)
                        } else {
                            (host_part, String::new(), path_part)
                        }
                    } else {
                        (host_part, String::new(), path_part)
                    }
                } else {
                    (host_port_part, String::new(), path_part)
                }
            } else {
                let (host_part, port_part) = if let Some(pos) = host_port_part.rfind(':') {
                    let port_str = &host_port_part[pos+1..];
                    if port_str.chars().all(|c| c.is_ascii_digit()) {
                        (&host_port_part[..pos], format!(":{}", port_str))
                    } else {
                        (host_port_part, String::new())
                    }
                } else {
                    (host_port_part, String::new())
                };
                (host_part, port_part, path_part)
            }
        };
        
        if host_part.chars().any(|c| !c.is_ascii()) {
            let ascii_host = domain_to_ascii(host_part)
                .map_err(|e| format!("Failed to convert IDN to ASCII: {}", e))?;
            let result = format!("{}://{}{}{}", scheme, ascii_host, port_part, path_part);
            Ok(result)
        } else {
            Ok(url_str.to_string())
        }
    } else {
        Ok(url_str.to_string())
    }
}
pub fn safe_convert_idn_to_ascii(url_str: &str) -> String {
    convert_idn_to_ascii(url_str).unwrap_or_else(|_| url_str.to_string())
}