use crate::{EncryptionHint, Policy, PolicyAxis};
use js_sys::{Array, Boolean, JsString, Reflect};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type Attributes;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "{name: string, isHybridized: boolean}")]
    pub type AttributeProperty;
}

#[wasm_bindgen]
pub fn webassembly_policy_axis(
    name: String,
    attribute_properties: Vec<AttributeProperty>,
    is_hierarchical: bool,
) -> Result<String, JsValue> {
    let attribute_properties = attribute_properties
        .into_iter()
        .map(|obj| -> Result<(String, EncryptionHint), JsValue> {
            let name = String::from(JsString::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = bool::from(Boolean::from(Reflect::get(
                &obj,
                &JsValue::from_str("name"),
            )?));
            let encryption_hint = if encryption_hint {
                EncryptionHint::Hybridized
            } else {
                EncryptionHint::Classic
            };
            Ok((name, encryption_hint))
        })
        .collect::<Result<Vec<_>, _>>()?;

    serde_json::to_string(&PolicyAxis::new(
        &name,
        attribute_properties
            .iter()
            .map(|(name, hint)| (name.as_str(), *hint))
            .collect(),
        is_hierarchical,
    ))
    .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_policy(nb_creations: u32) -> Result<String, JsValue> {
    serde_json::to_string(&Policy::new(nb_creations)).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn webassembly_add_axis(policy: String, axis: String) -> Result<String, JsValue> {
    let mut policy =
        Policy::parse_and_convert(&policy).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let axis: PolicyAxis =
        serde_json::from_str(&axis).map_err(|e| JsValue::from_str(&e.to_string()))?;
    policy.add_axis(axis)?;
    serde_json::to_string(&policy).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Rotates attributes, changing their underlying values with that of an unused
/// slot
///
/// - `attributes`  : user access policy (boolean expression as string)
/// - `policy`      : global policy data (JSON)
#[wasm_bindgen]
pub fn webassembly_rotate_attributes(
    attributes: Attributes,
    policy: String,
) -> Result<String, JsValue> {
    let attributes = Array::from(&JsValue::from(attributes));
    let mut policy = Policy::parse_and_convert(&policy)
        .map_err(|e| JsValue::from_str(&format!("Error deserializing policy: {e}")))?;

    // Rotate attributes of the current policy
    for attr in attributes.values() {
        let attribute = serde_json::from_str(String::from(JsString::from(attr?)).as_str())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        policy
            .rotate(&attribute)
            .map_err(|e| JsValue::from_str(&format!("Error rotating attribute: {e}")))?;
    }

    Ok(policy.to_string())
}
