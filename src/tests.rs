use crate::{error::Error, Attribute, Policy, PolicyAxis};

fn policy() -> Result<Policy, Error> {
    let sec_level = PolicyAxis::new(
        "Security Level",
        &["Protected", "Confidential", "Top Secret"],
        true,
    );
    let department = PolicyAxis::new("Department", &["R&D", "HR", "MKG", "FIN"], false);
    let mut policy = Policy::new(100);
    policy.add_axis(&sec_level)?;
    policy.add_axis(&department)?;
    // check that policy
    let attributes = policy.attributes();
    assert_eq!(sec_level.len() + department.len(), attributes.len());
    for att in sec_level.attributes() {
        assert!(attributes.contains(&Attribute::new("Security Level", att)))
    }
    for att in department.attributes() {
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
    println!("policy: {:?}", policy);
    for attribute in &attributes {
        assert_eq!(
            policy.attribute_values(attribute)?[0],
            policy.attribute_current_value(attribute)?
        )
    }
    Ok(())
}
