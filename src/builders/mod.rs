//! # Builders
//!
//! This module provides builder patterns for constructing cryptographic operations.
//!
//! ## Modules
//!
//! - [`pbkdf2_builder`] - Builder for PBKDF2-HMAC-SHA512 key derivation
//!
//! ## Usage
//!
//! Builders provide a fluent API for configuring cryptographic operations with
//! sensible defaults and optional customization.

pub mod pbkdf2_builder;
