//! Per-host bypass-path matching (Phase 9). Exact-match against a
//! conservatively normalized path, plus one narrow wildcard form: a
//! pattern ending in exactly `/*` matches that prefix (trailing slash
//! included) and everything under it. No general prefix/glob/regex
//! engine, and no attempt to mirror Caddy's own path-parsing behavior
//! exactly.
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
/// forwarded by Caddy) matches one of `bypass_paths`. Bypass paths are
/// themselves validated at config-load time to be either a clean
/// absolute path (exact match) or a clean absolute path ending in `/*`
/// (prefix match), so this is a plain comparison once the request side
/// is normalized.
pub fn matches_bypass(raw_target: &str, bypass_paths: &[String]) -> bool {
    match normalize_for_bypass_match(raw_target) {
        Some(normalized) => bypass_paths.iter().any(|p| path_matches(p, &normalized)),
        None => false,
    }
}

/// Compares one already-validated bypass-path pattern against an
/// already-normalized request path. `validate_bypass_path` guarantees at
/// config-load time that `pattern` is either a clean absolute path or a
/// clean absolute path ending in `/*` — no other `*` placement passes
/// validation, so only those two forms need handling here.
fn path_matches(pattern: &str, normalized: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => normalized.starts_with(prefix),
        None => pattern == normalized,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_path_matches() {
        assert!(matches_bypass("/healthz", &["/healthz".to_string()]));
        assert!(matches_bypass(
            "/static/logo.svg",
            &["/static/logo.svg".to_string()]
        ));
    }

    #[test]
    fn query_string_is_stripped_before_matching() {
        assert!(matches_bypass(
            "/healthz?foo=bar",
            &["/healthz".to_string()]
        ));
    }

    #[test]
    fn allowed_path_appended_as_a_query_string_on_a_protected_route_does_not_match() {
        // Regression test for the bypass-matching class of bug: an
        // attacker appending an allowed path to the query string of an
        // unrelated, protected route must not bypass auth on that route.
        assert!(!matches_bypass(
            "/admin/dashboard?x=/healthz",
            &["/healthz".to_string()]
        ));
        assert!(!matches_bypass(
            "/admin/dashboard?/healthz",
            &["/healthz".to_string()]
        ));
    }

    #[test]
    fn fragment_never_matches() {
        assert!(!matches_bypass("/healthz#frag", &["/healthz".to_string()]));
        assert!(!matches_bypass(
            "/healthz?x=1#frag",
            &["/healthz".to_string()]
        ));
    }

    #[test]
    fn double_encoding_never_matches() {
        // "%2568" decodes once to "%68", which still looks encoded —
        // rejected rather than decoded a second time to "h".
        assert!(!matches_bypass("/%2568ealthz", &["/healthz".to_string()]));
    }

    #[test]
    fn single_encoding_decodes_and_can_match() {
        assert!(matches_bypass("/%68ealthz", &["/healthz".to_string()]));
    }

    #[test]
    fn malformed_percent_encoding_never_matches() {
        assert!(!matches_bypass("/health%zz", &["/health%zz".to_string()]));
        assert!(!matches_bypass("/health%", &["/health%".to_string()]));
    }

    #[test]
    fn no_bypass_paths_configured_never_matches() {
        assert!(!matches_bypass("/healthz", &[]));
    }

    #[test]
    fn unrelated_path_does_not_match() {
        assert!(!matches_bypass("/other", &["/healthz".to_string()]));
    }

    #[test]
    fn wildcard_matches_prefix_and_everything_under_it() {
        let patterns = ["/share/*".to_string()];
        assert!(matches_bypass("/share/", &patterns));
        assert!(matches_bypass("/share/foo", &patterns));
        assert!(matches_bypass("/share/foo/bar.png", &patterns));
    }

    #[test]
    fn wildcard_does_not_match_bare_prefix_without_trailing_slash() {
        assert!(!matches_bypass("/share", &["/share/*".to_string()]));
    }

    #[test]
    fn wildcard_does_not_match_a_textually_similar_sibling_path() {
        assert!(!matches_bypass("/shared", &["/share/*".to_string()]));
        assert!(!matches_bypass("/share2/x", &["/share/*".to_string()]));
    }

    #[test]
    fn bare_wildcard_matches_everything() {
        assert!(matches_bypass("/anything", &["/*".to_string()]));
        assert!(matches_bypass("/", &["/*".to_string()]));
    }

    #[test]
    fn dot_segment_in_request_never_matches_even_under_a_wildcard() {
        let patterns = ["/public/*".to_string()];
        assert!(!matches_bypass("/public/../admin", &patterns));
        assert!(!matches_bypass("/public/%2e%2e/admin", &patterns));
    }

    #[test]
    fn double_slash_in_request_never_matches() {
        assert!(!matches_bypass("/public//admin", &["/public/*".to_string()]));
    }
}
