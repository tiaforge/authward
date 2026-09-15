//! Group-membership authorization (Phase 4).
//!
//! Group membership only — no arbitrary claim matching (the plan's
//! locked-in decision). No `required_group` configured on a host means
//! no check: any valid login passes, which is the default.

use serde_json::Value;

/// Checks whether `claims_json[claim_name]` contains `required_group`.
/// Accepts either the conventional JSON array of strings (pocket-id,
/// Keycloak, Authentik all shape it this way) or a single string. Any
/// other shape, or a missing/null claim, fails closed — an authorization
/// check that can't make sense of its input denies rather than guesses.
pub fn has_required_group(claims_json: &Value, claim_name: &str, required_group: &str) -> bool {
    match claims_json.get(claim_name) {
        Some(Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(required_group)),
        Some(Value::String(s)) => s == required_group,
        _ => false,
    }
}

/// Finds the first `path_required_groups` entry (in list order) whose
/// path pattern matches `raw_target`, if any — the same path-matching
/// rules as `bypass_paths` (exact match, or a trailing-`/*` prefix
/// match).
///
/// Returns `None` when `raw_target` is absent, fails the same
/// conservative normalization `bypass_paths` uses (dot-segments, `//`,
/// double-encoding, a fragment), or no entry matches. Unlike
/// `bypass_paths`, `None` here is safe: it never means "skip the check,"
/// only "no override for this request" — the caller still falls back to
/// the host's own, always-present `required_group`. An ambiguous or
/// non-canonical path therefore just narrows to the host's default
/// check rather than being denied outright, which is fine because the
/// alternative direction (treating it as a match when it might not be)
/// is what would actually be unsafe.
pub fn matching_path_required_group<'a>(
    raw_target: Option<&str>,
    overrides: &'a [crate::config::PathRequiredGroup],
) -> Option<&'a str> {
    let normalized = crate::bypass::normalize_for_bypass_match(raw_target?)?;
    overrides
        .iter()
        .find(|o| crate::bypass::path_matches(&o.path, &normalized))
        .map(|o| o.required_group.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn array_membership() {
        let claims = json!({"groups": ["admins", "users"]});
        assert!(has_required_group(&claims, "groups", "admins"));
        assert!(!has_required_group(&claims, "groups", "root"));
    }

    #[test]
    fn single_string_value() {
        let claims = json!({"groups": "admins"});
        assert!(has_required_group(&claims, "groups", "admins"));
        assert!(!has_required_group(&claims, "groups", "users"));
    }

    #[test]
    fn missing_or_wrong_shape_fails_closed() {
        assert!(!has_required_group(&json!({}), "groups", "admins"));
        assert!(!has_required_group(
            &json!({"groups": null}),
            "groups",
            "admins"
        ));
        assert!(!has_required_group(
            &json!({"groups": 42}),
            "groups",
            "admins"
        ));
        assert!(!has_required_group(
            &json!({"groups": [1, 2]}),
            "groups",
            "admins"
        ));
    }

    #[test]
    fn respects_configured_claim_name() {
        let claims = json!({"roles": ["admins"], "groups": []});
        assert!(has_required_group(&claims, "roles", "admins"));
        assert!(!has_required_group(&claims, "groups", "admins"));
    }

    fn overrides(entries: &[(&str, &str)]) -> Vec<crate::config::PathRequiredGroup> {
        entries
            .iter()
            .map(|(path, group)| crate::config::PathRequiredGroup {
                path: (*path).to_string(),
                required_group: (*group).to_string(),
            })
            .collect()
    }

    #[test]
    fn matching_path_required_group_finds_a_matching_entry() {
        let overrides = overrides(&[("/admin/*", "admins")]);
        assert_eq!(
            matching_path_required_group(Some("/admin/dashboard"), &overrides),
            Some("admins")
        );
    }

    #[test]
    fn matching_path_required_group_first_match_wins() {
        let overrides = overrides(&[("/admin/*", "admins"), ("/admin/reports/*", "reporters")]);
        assert_eq!(
            matching_path_required_group(Some("/admin/reports/q1"), &overrides),
            Some("admins"),
            "the first matching entry in list order wins, even if a later one is more specific"
        );
    }

    #[test]
    fn matching_path_required_group_no_match_returns_none() {
        let overrides = overrides(&[("/admin/*", "admins")]);
        assert_eq!(
            matching_path_required_group(Some("/public"), &overrides),
            None
        );
    }

    #[test]
    fn matching_path_required_group_ambiguous_input_returns_none() {
        let overrides = overrides(&[("/admin/*", "admins")]);
        assert_eq!(
            matching_path_required_group(Some("/admin/../admin/x"), &overrides),
            None
        );
        assert_eq!(matching_path_required_group(None, &overrides), None);
    }
}
