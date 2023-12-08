use crate::{
    error::MyError,
    group::{Group, ScalarMul},
    transcript::TranscriptReprTrait,
};
use core::ops::{Add, AddAssign};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

// use jf_primitives::pcs::StructuredReferenceString;

/////////////////////////////////////  trait bounds on commitment (point on base field)
/// com_a + com_b/com_a += com_b
pub trait CommitmentOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + AddAssign<Rhs>
{
}
/// com_a + &com_b/com_a += &com_b
pub trait CommitmentOpsOwned<Rhs = Self, Output = Self>:
    for<'r> CommitmentOps<&'r Rhs, Output>
{
}

/// empty implementation for bounds, make sure (check by Rust compiler) that any type T already implemented these traits
impl<T, Rhs, Output> CommitmentOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + AddAssign<Rhs>
{
}
impl<T, Rhs, Output> CommitmentOpsOwned<Rhs, Output> for T where
    T: for<'r> CommitmentOps<&'r Rhs, Output>
{
}

/////////////////////////////////////////////// A helper trait to absorb different objects in RO
pub trait AbsorbInROTrait<G: Group> {
    /// Absorbs the value in the provided RO
    fn absorb_in_ro(&self, ro: &mut G::RO);
}

/////////////////////////////////////////////// This trait defines the behavior of the commitment
pub trait CommitmentTrait<G: Group>:
    Clone
    + Copy
    + Debug
    + Default
    + PartialEq
    + Eq
    + TranscriptReprTrait<G>
    + Serialize
    + for<'de> Deserialize<'de>
    + AbsorbInROTrait<G>
    + CommitmentOps
    + CommitmentOpsOwned
    + ScalarMul<G::Scalar>
{
    /// Holds the type of the compressed commitment
    type CompressedCommitment: Clone
        + Debug
        + PartialEq
        + Eq
        // + Send
        // + Sync
        + TranscriptReprTrait<G>
        + Serialize
        + for<'de> Deserialize<'de>;

    /// Compresses self into a compressed commitment
    fn compress(&self) -> Self::CompressedCommitment;

    /// Returns the coordinate representation of the commitment
    fn to_coordinates(&self) -> (G::Base, G::Base, bool);

    /// Decompresses a compressed commitment into a commitment
    fn decompress(c: &Self::CompressedCommitment) -> Result<Self, MyError>;
}

/////////////////////////////////////////////// A trait that ties different pieces of the commitment generation together
pub trait CommitmentEngineTrait<G: Group>: Clone + Serialize + for<'de> Deserialize<'de> {
    // type SRS: Clone + Debug + StructuredReferenceString<G>;
    /// Holds the type of the commitment key
    type CommitmentKey: Clone + Debug + Serialize + for<'de> Deserialize<'de>;

    /// Holds the type of the commitment
    type Commitment: CommitmentTrait<G>;

    /// Samples a new commitment key of a specified size
    fn setup(label: &'static [u8], n: usize) -> Self::CommitmentKey;

    /// Commits to the provided vector using the provided generators
    fn commit(ck: &Self::CommitmentKey, v: &[G::Scalar]) -> Self::Commitment;
}
