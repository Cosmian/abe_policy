use crate::AccessPolicy;
use std::ffi::{c_char, c_int};

#[no_mangle]
/// Converts a boolean expression into an access policy.
///
/// - `access_policy_ptr`       : output access policy buffer
/// - `access_policy_len`       : size of the output buffer
/// - `boolean_expression_ptr`  : boolean access policy string
/// # Safety
pub unsafe extern "C" fn h_parse_boolean_access_policy(
    access_policy_ptr: *mut c_char,
    access_policy_len: *mut c_int,
    boolean_expression_ptr: *const c_char,
) -> c_int {
    let expr = read_ffi_string!("boolean_expression", boolean_expression_ptr);
    let access_policy = ffi_unwrap!(AccessPolicy::from_boolean_expression(&expr));

    let access_policy_bytes = ffi_unwrap!(serde_json::to_vec(&access_policy));

    write_ffi_bytes!(
        "access policy",
        &access_policy_bytes,
        access_policy_ptr,
        access_policy_len
    );

    0
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::interfaces::ffi::error::FfiError;
    use std::ffi::{c_int, CStr, CString};

    #[test]
    fn test_policy_expression_to_json() -> Result<(), FfiError> {
        let expr = "Department::   MKG && (   Country::France || Country::Spain)";
        let c_str = CString::new(expr)?;

        // use a large enough buffer size
        let mut large_enough = vec![0u8; 8192];
        let large_enough_ptr = large_enough.as_mut_ptr().cast();
        let mut large_enough_len = large_enough.len() as c_int;

        unsafe {
            let ler = h_parse_boolean_access_policy(
                large_enough_ptr,
                &mut large_enough_len,
                c_str.as_ptr(),
            );
            assert_eq!(0, ler);
            assert_eq!(98, large_enough_len);
            let le_json = CStr::from_ptr(large_enough_ptr);
            assert_eq!(
                r#"{"And":[{"Attr":"Department::MKG"},{"Or":[{"Attr":"Country::France"},{"Attr":"Country::Spain"}]}]}"#,
                le_json
                    .to_str()
                    .map_err(|e| FfiError::Generic(e.to_string()))?
            );
        };

        // use a buffer that is too small
        let mut too_small = vec![0u8; 8];
        let too_small_ptr = too_small.as_mut_ptr().cast();
        let mut too_small_len = too_small.len() as c_int;

        unsafe {
            let ler =
                h_parse_boolean_access_policy(too_small_ptr, &mut too_small_len, c_str.as_ptr());
            assert_eq!(98, ler);
        };

        Ok(())
    }
}
