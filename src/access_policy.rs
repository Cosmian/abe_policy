use crate::{policy::Policy, Attribute, Error};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{BitAnd, BitOr},
};

/// An `AccessPolicy` is a boolean expression over attributes.
///
/// Only `positive` literals are allowed (no negation).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AccessPolicy {
    Attr(Attribute),
    And(Box<AccessPolicy>, Box<AccessPolicy>),
    Or(Box<AccessPolicy>, Box<AccessPolicy>),
    All, // indicates we want the disjunction of all attributes
}

impl PartialEq for AccessPolicy {
    fn eq(&self, other: &Self) -> bool {
        let mut attributes_mapping = HashMap::<Attribute, u32>::new();
        let left_to_u32 = self.to_u32(&mut attributes_mapping);
        let right_to_u32 = other.to_u32(&mut attributes_mapping);
        if left_to_u32 != right_to_u32 {
            false
        } else {
            self.attributes() == other.attributes()
        }
    }
}

impl AccessPolicy {
    /// Creates an Access Policy based on a single Policy Attribute.
    ///
    /// Shortcut for
    /// ```ignore
    /// AccessPolicy::Attr(Attribute::new(axis, attribute))
    /// ```
    ///
    /// Access Policies can easily be created using it
    /// ```ignore
    /// let access_policy =
    ///     AccessPolicy::new("Security Level", "level 4")
    ///         & (AccessPolicy::new("Department", "MKG") | AccessPolicy::new("Department", "FIN"));
    /// ```
    #[must_use]
    pub fn new(axis: &str, attribute: &str) -> Self {
        Self::Attr(Attribute::new(axis, attribute))
    }

    /// Converts policy to integer value (for comparison).
    /// Each attribute is mapped to an integer value and the algebraic
    /// expression is applied with those values.
    /// We must keep a mapping of each attribute to the corresponding integer
    /// value in order to avoid having 2 different attributes with same integer
    /// value
    fn to_u32(&self, attribute_mapping: &mut HashMap<Attribute, u32>) -> u32 {
        match self {
            Self::Attr(attr) => {
                if let Some(integer_value) = attribute_mapping.get(attr) {
                    *integer_value
                } else {
                    let max = (attribute_mapping.len() + 1) as u32;
                    attribute_mapping.insert(attr.clone(), max);
                    max
                }
            }
            Self::And(l, r) => l.to_u32(attribute_mapping) * r.to_u32(attribute_mapping),
            Self::Or(l, r) => l.to_u32(attribute_mapping) + r.to_u32(attribute_mapping),
            Self::All => 0,
        }
    }

    /// Generates an access policy from a map of policy access names to policy
    /// attributes. The axes are `ORed` between each others while the attributes
    /// of each axis are `AND`ed.
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use abe_policy::AccessPolicy;
    ///
    /// let axes = serde_json::from_str(
    ///     r#"{
    ///     "Department": ["HR","FIN"],
    ///     "Level": ["level_2"]
    /// }"#
    /// )
    /// .unwrap();
    ///
    /// let access_policy = AccessPolicy::from_axes(&axes);
    /// assert_eq!(
    ///     access_policy.unwrap(),
    ///     (AccessPolicy::new("Department", "HR") | AccessPolicy::new("Department", "FIN")) & AccessPolicy::new("Level", "level_2"),
    /// );
    /// ```
    pub fn from_axes(axes_attributes: &HashMap<String, Vec<String>>) -> Result<Self, Error> {
        let mut access_policies = Vec::with_capacity(axes_attributes.len());
        for (axis, attributes) in axes_attributes {
            access_policies.push(
                attributes
                    .iter()
                    .map(|x| Attribute::new(axis, x).into())
                    .reduce(BitOr::bitor)
                    .ok_or_else(|| Error::MissingAttribute {
                        item: None,
                        axis_name: Some(axis.clone()),
                    })?,
            );
        }
        let access_policy = access_policies
            .iter()
            .cloned()
            .reduce(BitAnd::bitand)
            .ok_or(Error::MissingAxis)?;
        Ok(access_policy)
    }

    /// This function is finding the right closing parenthesis in the boolean
    /// expression given as a string
    fn find_next_parenthesis(boolean_expression: &str) -> Result<usize, Error> {
        let mut count = 0;
        let mut right_closing_parenthesis = None;
        for (index, c) in boolean_expression.chars().enumerate() {
            match c {
                '(' => count += 1,
                ')' => count -= 1,
                _ => {}
            };
            if count < 0 {
                right_closing_parenthesis = Some(index);
                break;
            }
        }

        right_closing_parenthesis.ok_or_else(|| {
            Error::InvalidBooleanExpression(format!(
                "Missing closing parenthesis in boolean expression {boolean_expression}"
            ))
        })
    }

    /// Sanitizes spaces in boolean expression around parenthesis and operators
    /// but keep spaces inside axis & attribute names.
    ///
    /// Useless spaces are removed:
    /// - before and after operator. Example: `A && B` --> `A&&B`
    /// - before and after parenthesis. Example: `(A && B)` --> `(A&&B)`
    /// - But keep these spaces: `(A::b c || d e::F)` --> `(A::b c||d e::F)`
    fn sanitize_spaces(boolean_expression: &str) -> String {
        let trim_closure = |expr: &str, separator: &str| -> String {
            let expression = expr
                .split(separator)
                .collect::<Vec<_>>()
                .into_iter()
                .map(str::trim)
                .collect::<Vec<_>>();
            let mut expression_chars = Vec::<char>::new();
            for (i, s) in expression.iter().enumerate() {
                if i == 0 && s.is_empty() {
                    expression_chars.append(&mut separator.chars().collect::<Vec<_>>());
                } else {
                    expression_chars.append(&mut s.chars().collect::<Vec<_>>());
                    if i != expression.len() - 1 {
                        expression_chars.append(&mut separator.chars().collect::<Vec<_>>());
                    }
                }
            }
            expression_chars.iter().collect::<String>()
        };

        // Remove successively spaces around `special` substrings
        let mut output = boolean_expression.to_string();
        for sep in ["(", ")", "||", "&&", "::"] {
            output = trim_closure(output.as_str(), sep);
        }

        output
    }

    /// This function takes a boolean expression and splits it into a left part,
    /// an operator and a right part.
    ///
    /// Example: "`Department::HR` && `Level::level_2`" will be decomposed in:
    /// - `Department::HR`
    /// - &&
    /// - `Level::level_2`
    fn decompose_expression(
        boolean_expression: &str,
        split_position: usize,
    ) -> Result<(String, Option<String>, Option<String>), Error> {
        /// Number of characters of an `AccessPolicy` operator.
        /// Possible operators are: '||' and '&&'.
        const OPERATOR_SIZE: usize = 2;

        if split_position > boolean_expression.len() {
            return Err(Error::InvalidBooleanExpression(format!(
                "Cannot split boolean expression {boolean_expression} at position \
                 {split_position} since {split_position} is greater than the size of \
                 {boolean_expression}"
            )));
        }

        // Put aside `Department::HR` from `Department::HR && Level::level_2`
        let left_part = &boolean_expression[..split_position];
        if split_position == boolean_expression.len() {
            return Ok((left_part.to_string(), None, None));
        }

        // Put aside `&&` from `Department::HR && Level::level_2`
        let next_char = boolean_expression
            .chars()
            .nth(split_position)
            .unwrap_or_default();
        let mut split_position = split_position;
        if next_char == ')' {
            split_position += 1;
        }
        if split_position == boolean_expression.len() {
            return Ok((left_part.to_string(), None, None));
        }
        if split_position + OPERATOR_SIZE > boolean_expression.len() {
            return Err(Error::InvalidBooleanExpression(format!(
                "Cannot split boolean expression {boolean_expression} at position \
                 {} since it is greater than the size of \
                 {boolean_expression}",
                split_position + OPERATOR_SIZE
            )));
        }

        let operator = &boolean_expression[split_position..split_position + OPERATOR_SIZE];

        // Put aside `Level::level_2` from `Department::HR && Level::level_2`
        let right_part = &boolean_expression[split_position + OPERATOR_SIZE..];
        Ok((
            left_part.to_string(),
            Some(operator.to_string()),
            Some(right_part.to_string()),
        ))
    }

    /// Converts a boolean expression into `AccessPolicy`.
    ///
    /// # Arguments
    ///
    /// - `boolean_expression`: expression with operators && and ||
    ///
    /// # Returns
    ///
    /// the corresponding `AccessPolicy`
    ///
    /// # Examples
    ///
    /// ```
    /// use abe_policy::AccessPolicy;
    ///
    /// let boolean_expression = "(Department::HR || Department::RnD) && Level::level_2";
    /// let access_policy = AccessPolicy::from_boolean_expression(boolean_expression);
    /// assert_eq!(
    ///     access_policy.unwrap(),
    ///     (AccessPolicy::new("Department", "HR") | AccessPolicy::new("Department", "RnD")) & AccessPolicy::new("Level", "level_2"),
    /// );
    /// ```
    /// # Errors
    ///
    /// Missing parenthesis or bad operators
    pub fn from_boolean_expression(boolean_expression: &str) -> Result<Self, Error> {
        let boolean_expression_example = "(Department::HR || Department::RnD) && Level::level_2";

        // Remove spaces around parenthesis and operators
        let boolean_expression = Self::sanitize_spaces(boolean_expression);

        if !boolean_expression.contains("::") {
            return Err(Error::InvalidBooleanExpression(format!(
                "'{boolean_expression}' does not contain any attribute separator '::'. Example: \
                 {boolean_expression_example}"
            )));
        }

        // if first char is parenthesis
        let first_char = boolean_expression.chars().next().unwrap_or_default();
        if first_char == '(' {
            // Skip first parenthesis
            let boolean_expression = &boolean_expression[1..];
            // Check if formula contains a closing parenthesis
            let c = boolean_expression.matches(')').count();
            if c == 0 {
                return Err(Error::InvalidBooleanExpression(format!(
                    "closing parenthesis missing in {boolean_expression}"
                )));
            }
            // Search right closing parenthesis, avoiding false positive
            let matching_closing_parenthesis = Self::find_next_parenthesis(boolean_expression)?;
            let (left_part, operator, right_part) =
                Self::decompose_expression(boolean_expression, matching_closing_parenthesis)?;
            if operator.is_none() {
                return Self::from_boolean_expression(left_part.as_str());
            }

            let operator = operator.unwrap_or_default();
            let right_part = right_part.unwrap_or_default();
            let ap1 = Box::new(Self::from_boolean_expression(left_part.as_str())?);
            let ap2 = Box::new(Self::from_boolean_expression(right_part.as_str())?);
            let ap = match operator.as_str() {
                "&&" => Ok(Self::And(ap1, ap2)),
                "||" => Ok(Self::Or(ap1, ap2)),
                _ => Err(Error::UnsupportedOperator(operator.to_string())),
            }?;
            Ok(ap)
        } else {
            let or_position = boolean_expression.find("||");
            let and_position = boolean_expression.find("&&");

            // Get position of next operator
            let position = if or_position.is_none() && and_position.is_none() {
                0
            } else if or_position.is_none() {
                and_position.unwrap_or_default()
            } else if and_position.is_none() {
                or_position.unwrap_or_default()
            } else {
                std::cmp::min(
                    or_position.unwrap_or_default(),
                    and_position.unwrap_or_default(),
                )
            };

            if position == 0 {
                let attribute_vec = boolean_expression.split("::").collect::<Vec<_>>();

                if attribute_vec.len() != 2
                    || attribute_vec[0].is_empty()
                    || attribute_vec[1].is_empty()
                {
                    return Err(Error::InvalidBooleanExpression(format!(
                        "'{boolean_expression}' does not respect the format <axis::name>. \
                         Example: {boolean_expression_example}"
                    )));
                }
                return Ok(Self::new(attribute_vec[0], attribute_vec[1]));
            }

            // Remove operator from input string
            let (left_part, operator, right_part) =
                Self::decompose_expression(&boolean_expression, position)?;
            if operator.is_none() {
                return Self::from_boolean_expression(left_part.as_str());
            }
            let operator = operator.unwrap_or_default();
            let right_part = right_part.unwrap_or_default();

            let ap1 = Box::new(Self::from_boolean_expression(left_part.as_str())?);
            let ap2 = Box::new(Self::from_boolean_expression(right_part.as_str())?);
            let ap = match operator.as_str() {
                "&&" => Ok(Self::And(ap1, ap2)),
                "||" => Ok(Self::Or(ap1, ap2)),
                _ => Err(Error::UnsupportedOperator(operator.to_string())),
            }?;

            Ok(ap)
        }
    }

    /// Retrieves all the attributes present in this access policy.
    ///
    /// The attributes are sorted. This is useful for comparisons.
    #[must_use]
    pub fn attributes(&self) -> Vec<Attribute> {
        let mut attributes = self._attributes();
        attributes.sort();
        attributes
    }

    fn _attributes(&self) -> Vec<Attribute> {
        match self {
            Self::Attr(att) => vec![att.clone()],
            Self::And(a1, a2) | Self::Or(a1, a2) => {
                let mut v = Self::_attributes(a1);
                v.extend(Self::_attributes(a2));
                v
            }

            Self::All => vec![],
        }
    }

    /// Returns the list of attribute combinations that can be built from the
    /// given access policy. It is an OR expression of AND expressions.
    ///
    /// - `policy`                      : global policy
    /// - `follow_hierarchical_axes`    : set to `true` to combine lower axis attributes
    pub fn to_attribute_combinations(
        &self,
        policy: &Policy,
        follow_hierarchical_axes: bool,
    ) -> Result<Vec<Vec<Attribute>>, Error> {
        match self {
            Self::Attr(attr) => {
                let axis_parameters = policy
                    .axes
                    .get(&attr.axis)
                    .ok_or_else(|| Error::InvalidAxis(attr.axis.clone()))?;
                let mut res = vec![vec![attr.clone()]];
                if axis_parameters.is_hierarchical && follow_hierarchical_axes {
                    // add attribute values for all attributes below the given one
                    for name in &axis_parameters.attribute_names {
                        if *name == attr.name {
                            break;
                        }
                        res.push(vec![Attribute::new(&attr.axis, name)]);
                    }
                }
                Ok(res)
            }
            Self::And(ap_left, ap_right) => {
                let combinations_left =
                    ap_left.to_attribute_combinations(policy, follow_hierarchical_axes)?;
                let combinations_right =
                    ap_right.to_attribute_combinations(policy, follow_hierarchical_axes)?;
                let mut res =
                    Vec::with_capacity(combinations_left.len() * combinations_right.len());
                for value_left in combinations_left {
                    for value_right in &combinations_right {
                        let mut combined = Vec::with_capacity(value_left.len() + value_right.len());
                        combined.extend_from_slice(&value_left);
                        combined.extend_from_slice(value_right);
                        res.push(combined)
                    }
                }
                Ok(res)
            }
            Self::Or(ap_left, ap_right) => {
                let combinations_left =
                    ap_left.to_attribute_combinations(policy, follow_hierarchical_axes)?;
                let combinations_right =
                    ap_right.to_attribute_combinations(policy, follow_hierarchical_axes)?;
                let mut res =
                    Vec::with_capacity(combinations_left.len() + combinations_right.len());
                res.extend(combinations_left);
                res.extend(combinations_right);
                Ok(res)
            }
            Self::All => Ok(vec![vec![]]),
        }
    }
}

// use A & B to construct And(A, B)
impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self::And(Box::new(self), Box::new(rhs))
    }
}

// use A | B to construct Or(A, B)
impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self::Or(Box::new(self), Box::new(rhs))
    }
}

impl From<Attribute> for AccessPolicy {
    fn from(attribute: Attribute) -> Self {
        Self::Attr(attribute)
    }
}
