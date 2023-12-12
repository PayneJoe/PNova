//! This module defines errors returned by the library.
use core::fmt::Debug;
use thiserror::Error;

/// Errors returned by Nova
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MyError {
    /// group error
    #[error("group error")]
    GroupError,
    /// keccak transcript error
    #[error("keccak error")]
    KeccakError,
    /// curve error
    #[error("curve error")]
    CurveError,
    /// hash error
    #[error("hash error")]
    HashError,
    /// commitment error
    #[error("commitment error")]
    CommitmentError,
    /// witness error
    #[error("witness erro")]
    WitnessError,
    /// public intput error
    #[error("public input error")]
    PublicIntputError,
}
