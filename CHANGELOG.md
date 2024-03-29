# Changelog

All notable changes to this project will be documented in this file.

## [3.0.4] - 2023-01-23

### Miscellaneous Tasks

- Must republish same code du to failed crates.io publish

---

## [3.0.3] - 2023-01-23

### Bug Fixes

- Enforce coherent naming

### Features

- Add FFI interface

---

## [3.0.2] - 2023-01-17

### Added

- `webassembly_parse_boolean_access_policy`

### Changed

- `webassembly_policy` -> return `Vec<u8>`
- `webassembly_add_axis` -> return `Vec<u8>`

### Fixed

### Removed

---

## [3.0.1] - 2023-01-17

### Added

### Changed

### Fixed

- `webassembly_rotate`

### Removed

---

## [3.0.0] - 2023-01-17

### Added

- wasm_bindgen interface

### Changed

- `Policy` format

### Fixed

### Removed

---

## [2.0.0] - 2023-01-04

### Added

- `AccessPolicy::to_attribute_combinations()`
- `Policy::attribute_hybridization_hint()`

### Changed

- `PolicyAxis::new()` signature
- `Policy::add_axis()` signature

### Fixed

### Removed

- `Policy::attribute_current_value()`

---

---

## [1.0.1] - 2022-08-24

### Added

### Changed

- make `attribute_to_int` public
- make `last_attribute_value` public

### Fixed

### Removed

---

---

## [1.0.0] - 2022-07-27

### Added

### Changed

- Add doc
- Several object internals have been made private
- review code for ANSSI submission

### Fixed

### Removed

- `ap()` is removed. Use `AccessPolicy::new()` instead

---

---

## [0.1.0] - 2022-07-06

### Added

- Create the library

### Changed

### Fixed

### Removed

---
