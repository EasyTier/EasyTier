use idna::domain_to_ascii;
pub fn convert_idn_to_ascii(url_str: &str) -> Result<String, String> {
    // Check if the URL string contains non-ASCII characters
    if url_str.chars().any(|c| !c.is_ascii()) {
        // Extract the scheme part
        let mut url_parts = url_str.splitn(2, "://");
        let scheme = url_parts.next().unwrap_or("");
        let rest = url_parts.next().unwrap_or(url_str);
        let mut path_parts = rest.splitn(2, '/');
        let host_port_part = path_parts.next().unwrap_or("");
        let path_part = path_parts.next().map(|s| format!("/{}", s)).unwrap_or_default();
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