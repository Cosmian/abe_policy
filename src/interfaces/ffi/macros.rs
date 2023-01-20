pub use std::ffi::CStr;

/// Return early with an error if a pointer is null
///
/// This macro is equivalent to
///  `
/// if ptr.is_null() {
///     set_last_error(FfiError::NullPointer($msg));
///     return 1;
/// }
/// `.
#[macro_export]
macro_rules! ffi_not_null {
    ($ptr:expr, $msg:expr) => {
        if $ptr.is_null() {
            $crate::interfaces::ffi::error::set_last_error(
                $crate::interfaces::ffi::error::FfiError::NullPointer($msg.to_owned()),
            );
            return 1_i32;
        }
    };
}

/// Unwrap a `std::result::Result`
///
/// If the result is in error, set the last error to its error and return 1
#[macro_export]
macro_rules! ffi_unwrap {
    ($result:expr, $msg:literal) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiError::Generic(format!("{}: {}", $msg, e)),
                );
                return 1_i32;
            }
        }
    };
    ($result:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                $crate::interfaces::ffi::error::set_last_error(
                    $crate::interfaces::ffi::error::FfiError::Generic(format!("{}", e)),
                );
                return 1_i32;
            }
        }
    };
}

/// Return early with an `FfiError::Generic` error if a condition is not
/// satisfied.
#[macro_export]
macro_rules! ffi_ensure {
    ($cond:expr, $msg:literal) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($msg.to_owned()));
            return 1_i32;
        }
    };
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic($err.to_string()));
            return 1_i32;
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::interfaces::ffi::error::set_last_error($crate::interfaces::ffi::error::FfiError::Generic(format!($fmt, $($arg)*)));
            return 1_i32;
        }
    };
}

/// Construct a generic error from a string, an ` Error` or an fmt expression.
#[macro_export]
macro_rules! ffi_error {
    ($msg:literal) => {
        $crate::interfaces::ffi::error::FfiError::Generic($msg.to_owned())
    };
    ($err:expr $(,)?) => ({
        $crate::interfaces::ffi::error::FfiError::Generic($err.to_string())
    });
    ($fmt:expr, $($arg:tt)*) => {
        $crate::interfaces::ffi::error::FfiError::Generic(format!($fmt, $($arg)*))
    };
}

/// Returns with an error.
#[macro_export]
macro_rules! ffi_bail {
    ($msg:expr) => {
        $crate::interfaces::ffi::error::set_last_error(
            $crate::interfaces::ffi::error::FfiError::Generic($msg),
        );
        return 1;
    };
    ($msg: expr, $error_code: expr) => {
        $crate::interfaces::ffi::error::set_last_error(
            $crate::interfaces::ffi::error::FfiError::Generic($msg.to_string()),
        );
        return $error_code;
    };
}

#[macro_export]
macro_rules! write_ffi_bytes {
    ($name: literal, $bytes: expr, $bytes_ptr: ident, $bytes_len: ident) => {
        $crate::ffi_not_null!(
            $bytes_ptr,
            format!("{} pointer should point to pre-allocated memory", $name)
        );

        let allocated = *$bytes_len;
        *$bytes_len = $bytes.len() as c_int;
        if allocated < *$bytes_len {
            $crate::ffi_bail!(
                format!("The pre-allocated {} buffer is too small; need {} bytes, allocated {allocated}", $name, *$bytes_len),
                $bytes.len() as c_int
            );
        }
        std::slice::from_raw_parts_mut($bytes_ptr.cast(), $bytes.len()).copy_from_slice($bytes);
    };
}

#[macro_export]
macro_rules! read_ffi_bytes {
    ($name: literal, $bytes_ptr: ident, $bytes_len: ident) => {{
        $crate::ffi_not_null!(
            $bytes_ptr,
            format!("{} pointer should point to pre-allocated memory", $name)
        );

        if $bytes_len == 0 {
            $crate::ffi_bail!(format!(
                "{} buffer should have a size greater than zero",
                $name
            ));
        }

        std::slice::from_raw_parts($bytes_ptr.cast(), $bytes_len as usize)
    }};
}

#[macro_export]
macro_rules! read_ffi_string {
    ($name: literal, $string_ptr: ident) => {{
        ffi_not_null!($string_ptr, format!("{} pointer should not be null", $name));

        match $crate::interfaces::ffi::macros::CStr::from_ptr($string_ptr).to_str() {
            Ok(msg) => msg.to_owned(),
            Err(e) => {
                ffi_bail!(format!("CoverCrypt keys generation: invalid Policy: {}", e));
            }
        }
    }};
}
