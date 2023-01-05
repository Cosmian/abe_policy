use crate::{error::Error, Attribute, EncryptionHint, Policy, PolicyAxis};

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
    policy.add_axis(sec_level.clone())?;
    policy.add_axis(department.clone())?;
    // check that policy
    let attributes = policy.attributes();
    assert_eq!(sec_level.len() + department.len(), attributes.len());
    for (att, _) in &sec_level.attribute_properties {
        assert!(attributes.contains(&Attribute::new("Security Level", att)))
    }
    for (att, _) in &department.attribute_properties {
        assert!(attributes.contains(&Attribute::new("Department", att)))
    }
    for attribute in &attributes {
        assert_eq!(
            policy.attribute_values(attribute)?[0],
            policy.attribute_current_value(attribute)?
        )
    }
    Ok(policy)
}

#[test]
fn test_rotate_policy_attributes() -> Result<(), Error> {
    let mut policy = policy()?;
    let attributes = policy.attributes();
    // rotate few attributes
    policy.rotate(&attributes[0])?;
    assert_eq!(2, policy.attribute_values(&attributes[0])?.len());
    policy.rotate(&attributes[2])?;
    assert_eq!(2, policy.attribute_values(&attributes[2])?.len());
    println!("policy: {policy:?}");
    for attribute in &attributes {
        assert_eq!(
            policy.attribute_values(attribute)?[0],
            policy.attribute_current_value(attribute)?
        )
    }
    Ok(())
}
