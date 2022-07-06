#![allow(clippy::module_name_repetitions)]

mod access_policy;
mod attribute;
pub mod error;
mod policy;

pub use access_policy::{ap, AccessPolicy};
pub use attribute::{Attribute, Attributes};
pub use policy::{Policy, PolicyAxis};

#[cfg(test)]
mod tests;
