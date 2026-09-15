//! Per-host bypass-path matching (Phase 9). Exact-match against a
//! conservatively normalized path, plus one narrow wildcard form: a
//! pattern ending in exactly `/*` matches that prefix (trailing slash
//! included) and everything under it. No general prefix/glob/regex
//! engine, and no attempt to mirror Caddy's own path-parsing behavior
//! exactly. Optionally, an entry can also be scoped to specific HTTP
//! methods, so e.g. a public read-only endpoint can bypass auth for
//! `GET`/`HEAD` without also exempting `DELETE`/`PUT`/`POST` on the same
//! path.
//!
//! Rather than risk a "confusion" bug if our normalization ever diverges
//! from Caddy's (the class of bug behind oauth2-proxy's fragment-
//! confusion CVE), normalization is maximally conservative: any path
//! containing a fragment marker, ambiguous/double percent-encoding, or
//! other non-canonical form is rejected outright — it falls through to
//! normal auth, never matched as a bypass. Wildcard matching adds a new
//! risk exact-matching didn't have: a path like `/public/../admin`
//! textually starts with `/public/` without semantically targeting that
//! subtree, so a decoded path containing a `.`/`..` segment or a `//` is
//! rejected outright too, regardless of which pattern it's checked
//! against. (Backslashes are deliberately not treated as separators —
//! this stack is Unix/Caddy/Axum, not IIS, and `\` has no path-separator
//! meaning anywhere in this pipeline.)

/// One `bypass_paths` entry, already validated at config-load time.
#[derive(Debug, Clone)]
pub struct BypassEntry {
    pub path: String,
    /// `None` = unrestricted, matches any request method (a bare-string
    /// config entry). `Some` = only these methods match; validated at
    /// config-load time to be known HTTP methods, uppercase-normalized.
    pub methods: Option<Vec<String>>,
}

impl BypassEntry {
    /// A bypass entry with no method restriction — matches any request
    /// method, same as a plain-string `bypass_paths` config entry.
    pub fn unrestricted(path: impl Into<String>) -> Self {
        BypassEntry {
            path: path.into(),
            methods: None,
        }
    }
}

/// Normalizes a raw request-target (as Caddy's `X-Forwarded-Uri` would
/// carry it: path plus optional `?query`) for bypass-path comparison.
/// Returns `None` for anything that isn't unambiguously a clean, single-
/// decoded, absolute path — callers must treat `None` as "does not match
/// any bypass rule", never as "matches everything" or "matches nothing
/// configured", to fail closed into normal auth.
pub fn normalize_for_bypass_match(raw_target: &str) -> Option<String> {
    // A fragment has no business being sent to a server at all (it's
    // stripped client-side before the request line is built); its
    // presence here is itself a sign of something non-canonical, so
    // reject rather than guess which part Caddy would have acted on.
    if raw_target.contains('#') {
        return None;
    }

    let path = raw_target.split('?').next().unwrap_or(raw_target);

    let decoded = percent_decode_once(path)?;

    // If the decoded output still contains what looks like a percent-
    // encoding, it was double-encoded (or the decode was ambiguous) —
    // reject rather than decode again and risk interpreting it the way
    // an attacker intended but a literal single-decode wouldn't.
    if looks_percent_encoded(&decoded) {
        return None;
    }

    if !decoded.starts_with('/') {
        return None;
    }

    // A dot-segment or empty segment could make a path textually start
    // with an allowed prefix while semantically targeting somewhere else
    // once resolved — reject outright rather than guess at resolution.
    if decoded.contains("//") || decoded.split('/').any(|s| s == "." || s == "..") {
        return None;
    }

    Some(decoded)
}

fn percent_decode_once(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex_str = std::str::from_utf8(hex).ok()?;
            let byte = u8::from_str_radix(hex_str, 16).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn looks_percent_encoded(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && bytes
                .get(i + 1..i + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether `raw_target` (the original app request's path+query, as
/// forwarded by Caddy) and `method` (as Caddy's `X-Forwarded-Method`
/// would carry it) match one of `bypass_paths`. Bypass paths are
/// themselves validated at config-load time to be either a clean
/// absolute path (exact match) or a clean absolute path ending in `/*`
/// (prefix match), so this is a plain comparison once the request side
/// is normalized.
pub fn matches_bypass(
    raw_target: &str,
    method: Option<&str>,
    bypass_paths: &[BypassEntry],
) -> bool {
    match normalize_for_bypass_match(raw_target) {
        Some(normalized) => bypass_paths.iter().any(|entry| {
            path_matches(&entry.path, &normalized)
                && method_matches(entry.methods.as_deref(), method)
        }),
        None => false,
    }
}

/// Compares one already-validated bypass-path pattern against an
/// already-normalized request path. `validate_bypass_path` guarantees at
/// config-load time that `pattern` is either a clean absolute path or a
/// clean absolute path ending in `/*` — no other `*` placement passes
/// validation, so only those two forms need handling here.
pub(crate) fn path_matches(pattern: &str, normalized: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => normalized.starts_with(prefix),
        None => pattern == normalized,
    }
}

/// `None` (unrestricted) always matches. `Some(list)` requires the
/// request's method to be known and case-insensitively present in
/// `list` — fails closed (no match) if the method can't be determined,
/// deliberately different from this codebase's fail-open-to-GET
/// precedent for `X-Forwarded-Method` elsewhere (`unauthorized()`),
/// because that precedent picks which 401 body to return, not whether to
/// skip auth entirely.
fn method_matches(allowed: Option<&[String]>, method: Option<&str>) -> bool {
    match allowed {
        None => true,
        Some(list) => method.is_some_and(|m| list.iter().any(|a| a.eq_ignore_ascii_case(m))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unrestricted(paths: &[&str]) -> Vec<BypassEntry> {
        paths
            .iter()
            .map(|p| BypassEntry::unrestricted(*p))
            .collect()
    }

    #[test]
    fn exact_path_matches() {
        assert!(matches_bypass(
            "/healthz",
            None,
            &unrestricted(&["/healthz"])
        ));
        assert!(matches_bypass(
            "/static/logo.svg",
            None,
            &unrestricted(&["/static/logo.svg"])
        ));
    }

    #[test]
    fn query_string_is_stripped_before_matching() {
        assert!(matches_bypass(
            "/healthz?foo=bar",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn allowed_path_appended_as_a_query_string_on_a_protected_route_does_not_match() {
        // Regression test for the bypass-matching class of bug: an
        // attacker appending an allowed path to the query string of an
        // unrelated, protected route must not bypass auth on that route.
        assert!(!matches_bypass(
            "/admin/dashboard?x=/healthz",
            None,
            &unrestricted(&["/healthz"])
        ));
        assert!(!matches_bypass(
            "/admin/dashboard?/healthz",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn fragment_never_matches() {
        assert!(!matches_bypass(
            "/healthz#frag",
            None,
            &unrestricted(&["/healthz"])
        ));
        assert!(!matches_bypass(
            "/healthz?x=1#frag",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn double_encoding_never_matches() {
        // "%2568" decodes once to "%68", which still looks encoded —
        // rejected rather than decoded a second time to "h".
        assert!(!matches_bypass(
            "/%2568ealthz",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn single_encoding_decodes_and_can_match() {
        assert!(matches_bypass(
            "/%68ealthz",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn malformed_percent_encoding_never_matches() {
        assert!(!matches_bypass(
            "/health%zz",
            None,
            &unrestricted(&["/health%zz"])
        ));
        assert!(!matches_bypass(
            "/health%",
            None,
            &unrestricted(&["/health%"])
        ));
    }

    #[test]
    fn no_bypass_paths_configured_never_matches() {
        assert!(!matches_bypass("/healthz", None, &[]));
    }

    #[test]
    fn unrelated_path_does_not_match() {
        assert!(!matches_bypass(
            "/other",
            None,
            &unrestricted(&["/healthz"])
        ));
    }

    #[test]
    fn wildcard_matches_prefix_and_everything_under_it() {
        let patterns = unrestricted(&["/share/*"]);
        assert!(matches_bypass("/share/", None, &patterns));
        assert!(matches_bypass("/share/foo", None, &patterns));
        assert!(matches_bypass("/share/foo/bar.png", None, &patterns));
    }

    #[test]
    fn wildcard_does_not_match_bare_prefix_without_trailing_slash() {
        assert!(!matches_bypass(
            "/share",
            None,
            &unrestricted(&["/share/*"])
        ));
    }

    #[test]
    fn wildcard_does_not_match_a_textually_similar_sibling_path() {
        assert!(!matches_bypass(
            "/shared",
            None,
            &unrestricted(&["/share/*"])
        ));
        assert!(!matches_bypass(
            "/share2/x",
            None,
            &unrestricted(&["/share/*"])
        ));
    }

    #[test]
    fn bare_wildcard_matches_everything() {
        assert!(matches_bypass("/anything", None, &unrestricted(&["/*"])));
        assert!(matches_bypass("/", None, &unrestricted(&["/*"])));
    }

    #[test]
    fn dot_segment_in_request_never_matches_even_under_a_wildcard() {
        let patterns = unrestricted(&["/public/*"]);
        assert!(!matches_bypass("/public/../admin", None, &patterns));
        assert!(!matches_bypass("/public/%2e%2e/admin", None, &patterns));
    }

    #[test]
    fn double_slash_in_request_never_matches() {
        assert!(!matches_bypass(
            "/public//admin",
            None,
            &unrestricted(&["/public/*"])
        ));
    }

    #[test]
    fn scoped_bypass_matches_only_configured_methods() {
        let entries = [BypassEntry {
            path: "/api/assets/*".to_string(),
            methods: Some(vec!["GET".to_string(), "HEAD".to_string()]),
        }];
        assert!(matches_bypass("/api/assets/1", Some("GET"), &entries));
        assert!(matches_bypass("/api/assets/1", Some("HEAD"), &entries));
    }

    #[test]
    fn scoped_bypass_denies_unconfigured_method() {
        let entries = [BypassEntry {
            path: "/api/assets/*".to_string(),
            methods: Some(vec!["GET".to_string(), "HEAD".to_string()]),
        }];
        assert!(!matches_bypass("/api/assets/1", Some("DELETE"), &entries));
        assert!(!matches_bypass("/api/assets/1", Some("PUT"), &entries));
        assert!(!matches_bypass("/api/assets/1", Some("POST"), &entries));
    }

    #[test]
    fn scoped_bypass_method_match_is_case_insensitive() {
        let entries = [BypassEntry {
            path: "/api/assets/*".to_string(),
            methods: Some(vec!["GET".to_string()]),
        }];
        assert!(matches_bypass("/api/assets/1", Some("get"), &entries));
    }

    #[test]
    fn scoped_bypass_fails_closed_when_method_is_unknown() {
        let entries = [BypassEntry {
            path: "/api/assets/*".to_string(),
            methods: Some(vec!["GET".to_string()]),
        }];
        assert!(!matches_bypass("/api/assets/1", None, &entries));
    }

    #[test]
    fn unrestricted_entry_ignores_method() {
        let entries = unrestricted(&["/healthz"]);
        assert!(matches_bypass("/healthz", Some("DELETE"), &entries));
        assert!(matches_bypass("/healthz", None, &entries));
    }
}
