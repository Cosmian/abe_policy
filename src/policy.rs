#![allow(clippy::module_name_repetitions)]

use crate::{Attribute, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BinaryHeap, HashMap},
    fmt::{Debug, Display},
};

/// Defines a policy axis by its name and its underlying attribute names.
///
/// If `hierarchical` is set to `true`, we assume a lexicographical order based
/// on the attribute name.
#[derive(Clone, Deserialize)]
pub struct PolicyAxis {
    name: String,
    attributes: Vec<String>,
    hierarchical: bool,
}

impl PolicyAxis {
    /// Generate a new policy axis with the given name and attribute names. A
    /// hierarchical axis enforce order between its attributes.
    ///
    /// - `name`        : axis name
    /// - `attributes`  : name of the attributes on this axis
    /// - `hierarchical`: set the axis to be hierarchical
    #[must_use]
    pub fn new(name: &str, attributes: &[&str], hierarchical: bool) -> Self {
        Self {
            name: name.to_owned(),
            attributes: attributes.iter().map(|s| (*s).to_string()).collect(),
            hierarchical,
        }
    }

    /// Returns the number of attributes belonging to this axis.
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Returns the list of attribute names belonging to this axis.
    pub fn attributes(&self) -> &[String] {
        &self.attributes
    }

    /// Returns the axis name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return `true` if this axis is hierarchical.
    pub fn is_hierarchical(&self) -> bool {
        self.hierarchical
    }
}

/// A policy is a set of policy axes. A fixed number of attribute creations
/// (revocations + additions) is allowed.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Policy {
    /// Last value taken by the attriute.
    last_attribute_value: u32,
    /// Maximum attribute value. Defines a maximum number of attribute
    /// creations (revocations + addition).
    max_attribute_value: u32,
    /// Policy axes
    axes: HashMap<String, (Vec<String>, bool)>,
    /// mapping between attribute -> integer
    attribute_to_int: HashMap<Attribute, BinaryHeap<u32>>,
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json = serde_json::to_string(&self);
        match json {
            Ok(string) => write!(f, "{}", string),
            Err(err) => write!(f, "{}", err),
        }
    }
}

impl Policy {
    /// Generates a new policy object with the given number of attribute
    /// creation (revocation + addition) allowed.
    #[must_use]
    pub fn new(nb_creations: u32) -> Self {
        Self {
            last_attribute_value: 0,
            max_attribute_value: nb_creations,
            axes: HashMap::new(),
            attribute_to_int: HashMap::new(),
        }
    }

    /// Returns the policy in the form of a Map where
    ///  - the keys are the axis names
    ///  - the values are a tuple of
    ///     - list of attribute names for that axis
    ///     - whether the axis hierarchical
    pub fn as_map(&self) -> &HashMap<String, (Vec<String>, bool)> {
        &self.axes
    }

    /// Return the number of attribute creations allowed.
    #[must_use]
    pub fn max_attr(&self) -> u32 {
        self.max_attribute_value
    }

    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: &PolicyAxis) -> Result<(), Error> {
        if axis.len() > u32::MAX as usize {
            return Err(Error::CapacityOverflow);
        }
        if (axis.len() as u32) + self.last_attribute_value > self.max_attribute_value {
            return Err(Error::CapacityOverflow);
        }
        // insert new policy
        if self.axes.contains_key(&axis.name) {
            return Err(Error::ExistingPolicy(axis.name.clone()));
        } else {
            self.axes.insert(
                axis.name.clone(),
                (axis.attributes.clone(), axis.hierarchical),
            );
        }

        for attr in &axis.attributes {
            self.last_attribute_value += 1;
            if self
                .attribute_to_int
                .insert(
                    (axis.name.clone(), attr.clone()).into(),
                    vec![self.last_attribute_value].into(),
                )
                .is_some()
            {
                // must never occurs as policy is a new one
                return Err(Error::ExistingPolicy(axis.name.clone()));
            }
        }
        Ok(())
    }

    /// Rotates an attribute, changing its underlying value with that of an
    /// unused slot.
    pub fn rotate(&mut self, attr: &Attribute) -> Result<(), Error> {
        if self.last_attribute_value == self.max_attribute_value {
            Err(Error::CapacityOverflow)
        } else if let Some(heap) = self.attribute_to_int.get_mut(attr) {
            self.last_attribute_value += 1;
            heap.push(self.last_attribute_value);
            Ok(())
        } else {
            Err(Error::AttributeNotFound(format!("{:?}", attr)))
        }
    }

    /// Returns the list of Attributes of this Policy.
    pub fn attributes(&self) -> Vec<Attribute> {
        self.attribute_to_int
            .keys()
            .cloned()
            .collect::<Vec<Attribute>>()
    }

    /// Returns the list of all attributes values given to this Attribute
    /// over the time after rotations. The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> Result<Vec<u32>, Error> {
        let mut v = self
            .attribute_to_int
            .get(attribute)
            .cloned()
            .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))?
            .into_sorted_vec();
        v.reverse();
        Ok(v)
    }

    /// Retrieves the current value of an attribute.
    pub fn attribute_current_value(&self, attribute: &Attribute) -> Result<u32, Error> {
        let values = self.attribute_values(attribute)?;
        values
            .first()
            .ok_or_else(|| {
                Error::InvalidAttribute(format!(
                    "the attribute {} does not have any value!",
                    attribute
                ))
            })
            .cloned()
    }

    /// Retrieves the current attribute values for the `Attribute` list
    pub fn attributes_values(&self, attributes: &[Attribute]) -> Result<Vec<u32>, Error> {
        let mut values: Vec<u32> = Vec::with_capacity(attributes.len());
        for att in attributes {
            let v = self
                .attribute_to_int
                .get(att)
                .and_then(std::collections::BinaryHeap::peek)
                .ok_or_else(|| Error::AttributeNotFound(format!("{:?}", att)))?;
            values.push(*v);
        }
        Ok(values)
    }
}
