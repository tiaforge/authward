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
}
