//////////////////////////////////////////// circuit-friendly hash trait, for the convenience of verification of folding
///
///
use serde::{Deserialize, Serialize};

pub trait ROConstantsTrait<Base> {
    /// produces constants/parameters associated with the hash function
    fn new() -> Self;
}

/// A helper trait that defines the constants associated with a hash function
pub trait ROTrait<Base, Scalar> {
    /// A type representing constants/parameters associated with the hash function
    type Constants: ROConstantsTrait<Base> + Clone + Serialize + for<'de> Deserialize<'de>;

    /// Initializes the hash function
    fn new(constants: Self::Constants, num_absorbs: usize) -> Self;

    /// Adds a scalar to the internal state
    fn absorb(&mut self, e: Base);

    /// Returns a challenge of `num_bits` by hashing the internal state
    fn squeeze(&mut self, num_bits: usize) -> Scalar;
}
