use abe_policy::{EncryptionHint, Error, LegacyPolicy, Policy, PolicyAxis};
use std::{fs::File, io::Read, path::Path};

/// Generate a new policy.
fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        vec![
            ("Protected", EncryptionHint::Classic),
            ("Confidential", EncryptionHint::Classic),
            ("Top Secret", EncryptionHint::Hybridized),
        ],
        true,
    );
    let department = PolicyAxis::new(
        "Department",
        vec![
            ("R&D", EncryptionHint::Classic),
            ("HR", EncryptionHint::Classic),
            ("MKG", EncryptionHint::Classic),
            ("FIN", EncryptionHint::Classic),
        ],
        false,
    );
    let mut policy = Policy::new(100);
    policy.add_axis(sec_level)?;
    policy.add_axis(department)?;
    Ok(policy)
}

/// Write the policy to a file.
#[test]
fn write_policy() {
    let policy = policy().unwrap();
    std::fs::write("tests/policy.json", serde_json::to_string(&policy).unwrap()).unwrap();
}

/// Read policy from a file.
#[test]
fn read_policy() {
    // read policy
    let policy_str = include_str!("policy.json");
    let _policy = serde_json::from_str::<Policy>(policy_str).unwrap();

    // read legacy policy
    let legacy_policy_str = include_str!("legacy_policy.json");
    let _legacy_policy = serde_json::from_str::<LegacyPolicy>(legacy_policy_str).unwrap();

    // read legacy policy as current policy
    let _policy = Policy::parse_and_convert(legacy_policy_str).unwrap();
}
