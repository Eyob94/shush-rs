# Changelog

### 0.1.11 - 2024-10-29
- [#15] (https://github.com/Eyob94/shush-rs/pull/14) Page size caching
    - Cache page size and store it in a lazycell instead of calling it multiple times

### 0.1.10 - 2024-09-14

- [#14] (https://github.com/Eyob94/shush-rs/pull/14) Breaking changes
  - Rename `from_vec` to `from`

### 0.1.9 - 2024-09-13

- [#13] (https://github.com/Eyob94/shush-rs/pull/13) Public interface
  - Publicize `from_vec` for SecretVec

### 0.1.8 - 2024-09-13

- [#12] (https://github.com/Eyob94/shush-rs/pull/12) SecretVec
  - Implement `from_vec` for SecretVec

### 0.1.7 - 2024-09-13

- [#11] (https://github.com/Eyob94/shush-rs/pull/11) String
  - Implement Display for SecretGuard & SecretGuardMut

## 0.1.6 - 2024-09-11

- [#10](https://github.com/Eyob94/shush-rs/pull/10) SecretVec
  - Add public alias and `SecretVec`

## 0.1.5 - 2024-09-11

- [#10](https://github.com/Eyob94/shush-rs/pull/9) FromStr
  - Implement `FromStr` trait for SecretString
  - Add public alias `SecretString` and `SecretVec`

## 0.1.4 - 2024-09-11

- [#9](https://github.com/Eyob94/shush-rs/pull/9) Mutable Reference
  - Remove Mutable Reference for `expose_secret()`

## 0.1.3 - 2024-09-11

- [#8](https://github.com/Eyob94/shush-rs/pull/8) Impl Trait
  - Implement CloneableSecret Trait for String

## 0.1.2 - 2024-09-11

- [#7](https://github.com/Eyob94/shush-rs/pull/7) Add Changelog
  - Add Changelog

## 0.1.1 - 2024-09-11

- [#6](https://github.com/Eyob94/shush-rs/pull/6) Eq and PartialEq
  - Derive `Eq` and `PartialEq` for `SecretGuard` and `SecretGuardMut`

## 0.1.0 - 2024-09-08

- [#5](https://github.com/Eyob94/shush-rs/pull/5) Initial Pre-release
  - Add `mlock` and `munlock` along with proper page size alignment
