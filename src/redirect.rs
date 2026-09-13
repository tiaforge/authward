//! Open-redirect validation, shared by every redirect target this service
//! ever follows: `/login`'s `rd` parameter, the post-callback redirect, and
//! (Phase 8) the post-logout redirect. One implementation, one set of
//! tests, no separate less-strict code path for any of them.

use url::Url;

/// Returns the target unchanged if it's an absolute http(s) URL whose host
/// is the given base domain or a subdomain of it; `None` otherwise (callers
/// should fall back to a safe default, never to the unvalidated input).
pub fn validate_redirect_target(target: &str, base_domain: &str) -> Option<String> {
    let url = Url::parse(target).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    let base_domain = base_domain.to_ascii_lowercase();
    if host == base_domain || host.ends_with(&format!(".{base_domain}")) {
        Some(url.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_same_base_domain_and_subdomains() {
        assert_eq!(
            validate_redirect_target("https://app.example.com/x", "example.com"),
            Some("https://app.example.com/x".to_string())
        );
        assert_eq!(
            validate_redirect_target("https://example.com/", "example.com"),
            Some("https://example.com/".to_string())
        );
    }

    #[test]
    fn rejects_other_hosts() {
        assert_eq!(
            validate_redirect_target("https://evil.com/", "example.com"),
            None
        );
        // Suffix confusion: "notexample.com" is not "*.example.com".
        assert_eq!(
            validate_redirect_target("https://notexample.com/", "example.com"),
            None
        );
        // Lookalike: "example.com.evil.com" ends with "evil.com", not our base domain.
        assert_eq!(
            validate_redirect_target("https://example.com.evil.com/", "example.com"),
            None
        );
    }

    #[test]
    fn rejects_non_http_schemes_and_garbage() {
        assert_eq!(
            validate_redirect_target("javascript:alert(1)", "example.com"),
            None
        );
        assert_eq!(validate_redirect_target("not a url", "example.com"), None);
        assert_eq!(
            validate_redirect_target("/relative/path", "example.com"),
            None
        );
    }
}
