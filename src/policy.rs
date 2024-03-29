use crate::{Attribute, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    ops::BitOr,
};

/// Hint the user about which kind of encryption to use.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionHint {
    /// Hybridized encryption should be used.
    Hybridized,
    /// Classic encryption should be used.
    Classic,
}

impl BitOr for EncryptionHint {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Hybridized || rhs == Self::Hybridized {
            Self::Hybridized
        } else {
            Self::Classic
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxisAttributePorperties {
    pub name: String,
    pub encryption_hint: EncryptionHint,
}

/// Defines a policy axis by its name and its underlying attribute properties.
/// An attribute property defines its name and a hint about whether hybridized
/// encryption should be used for it (hint set to `true` if this is the case).
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAxis {
    /// Axis name
    pub name: String,
    /// Names of the axis attributes and hybridized encryption hints
    pub attributes_properties: Vec<AxisAttributePorperties>,
    /// `true` if the axis is hierarchical
    pub hierarchical: bool,
}

impl PolicyAxis {
    /// Generates a new policy axis with the given name and attribute names.
    /// A hierarchical axis enforces order between its attributes.
    ///
    /// - `name`                    : axis name
    /// - `attribute_properties`    : axis attribute properties
    /// - `hierarchical`            : set to `true` if the axis is hierarchical
    #[must_use]
    pub fn new(
        name: &str,
        attributes_properties: Vec<(&str, EncryptionHint)>,
        hierarchical: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            attributes_properties: attributes_properties
                .into_iter()
                .map(|(axis_name, encryption_hint)| AxisAttributePorperties {
                    name: axis_name.to_string(),
                    encryption_hint,
                })
                .collect(),
            hierarchical,
        }
    }

    /// Returns the number of attributes belonging to this axis.
    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes_properties.len()
    }

    /// Return `true` if the attribute list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes_properties.is_empty()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyAxesParameters {
    pub attribute_names: Vec<String>,
    pub is_hierarchical: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PolicyAttributesParameters {
    pub values: Vec<u32>,
    pub encryption_hint: EncryptionHint,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LegacyPolicy {
    /// Last value taken by the attriute.
    pub(crate) last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    pub max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, Vec<u32>>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyVersion {
    V1,
}

/// A policy is a set of policy axes. A fixed number of attribute creations
/// (revocations + additions) is allowed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Policy {
    /// Version number
    pub version: PolicyVersion,
    /// Last value taken by the attriute.
    pub(crate) last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    pub max_attribute_creations: u32,
    /// Policy axes: maps axes name to the list of associated attribute names
    /// and a boolean defining whether or not this axis is hierarchical.
    pub axes: HashMap<String, PolicyAxesParameters>,
    /// Maps an attribute to its values and its hybridization hint.
    pub attributes: HashMap<Attribute, PolicyAttributesParameters>,
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(&self);
        match json {
            Ok(string) => write!(f, "{string}"),
            Err(err) => write!(f, "{err}"),
        }
    }
}

impl Policy {
    /// Converts the given string into a Policy. Does not fail if the given
    /// string uses the legacy format.
    pub fn parse_and_convert(bytes: &[u8]) -> Result<Self, Error> {
        match serde_json::from_slice(bytes) {
            Ok(policy) => Ok(policy),
            Err(e) => {
                if let Ok(policy) = serde_json::from_slice::<LegacyPolicy>(bytes) {
                    // Convert the legacy format to the current one.
                    Ok(Self {
                        version: PolicyVersion::V1,
                        max_attribute_creations: policy.max_attribute_creations,
                        last_attribute_value: policy.last_attribute_value,
                        axes: policy.axes,
                        attributes: policy
                            .attributes
                            .into_iter()
                            .map(|(name, values)| {
                                (
                                    name,
                                    PolicyAttributesParameters {
                                        values,
                                        encryption_hint: EncryptionHint::Classic,
                                    },
                                )
                            })
                            .collect(),
                    })
                } else {
                    // Return the `Policy` deserialization error message instead of the
                    // `LegacyPolicy` one since this is the one that should be used.
                    Err(Error::DeserializationError(e))
                }
            }
        }
    }

    /// Generates a new policy object with the given number of attribute
    /// creation (revocation + addition) allowed.
    #[inline]
    #[must_use]
    pub fn new(nb_creations: u32) -> Self {
        Self {
            version: PolicyVersion::V1,
            last_attribute_value: 0,
            max_attribute_creations: nb_creations,
            axes: HashMap::new(),
            attributes: HashMap::new(),
        }
    }

    /// Returns the remaining number of allowed attribute creations (additions + rotations).
    #[inline]
    #[must_use]
    pub fn remaining_attribute_creations(&self) -> u32 {
        self.max_attribute_creations - self.last_attribute_value
    }

    /// Returns the policy in the form of a Map where
    ///  - the keys are the axis names
    ///  - the values are a tuple of
    ///     - list of attribute names for that axis
    ///     - whether the axis hierarchical
    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: PolicyAxis) -> Result<(), Error> {
        if axis.len() > (self.max_attribute_creations - self.last_attribute_value) as usize {
            return Err(Error::CapacityOverflow);
        }
        if self.axes.get(&axis.name).is_some() {
            return Err(Error::ExistingPolicy(axis.name));
        }
        let mut axis_attributes = Vec::with_capacity(axis.attributes_properties.len());

        for properties in axis.attributes_properties {
            self.last_attribute_value += 1;
            axis_attributes.push(properties.name.clone());
            let attribute = (axis.name.clone(), properties.name.clone()).into();
            if self.attributes.get(&attribute).is_some() {
                return Err(Error::ExistingPolicy(format!("{attribute:?}")));
            }
            self.attributes.insert(
                attribute,
                PolicyAttributesParameters {
                    values: [self.last_attribute_value].into(),
                    encryption_hint: properties.encryption_hint,
                },
            );
        }

        self.axes.insert(
            axis.name,
            PolicyAxesParameters {
                attribute_names: axis_attributes,
                is_hierarchical: axis.hierarchical,
            },
        );

        Ok(())
    }

    /// Rotates an attribute, changing its underlying value with an unused
    /// value.
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), Error> {
        if self.last_attribute_value == self.max_attribute_creations {
            Err(Error::CapacityOverflow)
        } else if let Some(attribute_parameters) = self.attributes.get_mut(attr) {
            self.last_attribute_value += 1;
            attribute_parameters.values.push(self.last_attribute_value);
            Ok(())
        } else {
            Err(Error::AttributeNotFound(attr.to_string()))
        }
    }

    /// Returns the list of Attributes of this Policy.
    #[inline]
    #[must_use]
    pub fn attributes(&self) -> Vec<Attribute> {
        self.attributes.keys().cloned().collect::<Vec<Attribute>>()
    }

    /// Returns the list of all values given to this attribute over rotations.
    /// The current value is returned first
    #[inline]
    pub fn attribute_values(&self, attribute: &Attribute) -> Result<Vec<u32>, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| attribute_parameters.values.iter().rev().copied().collect())
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }

    /// Returns the hybridization hint of the given attribute.
    #[inline]
    pub fn attribute_hybridization_hint(
        &self,
        attribute: &Attribute,
    ) -> Result<EncryptionHint, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| attribute_parameters.encryption_hint)
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }

    /// Retrieves the current value of an attribute.
    #[inline]
    pub fn attribute_current_value(&self, attribute: &Attribute) -> Result<u32, Error> {
        self.attributes
            .get(attribute)
            .map(|attribute_parameters| {
                attribute_parameters.values[attribute_parameters.values.len() - 1]
            })
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))
    }
}
