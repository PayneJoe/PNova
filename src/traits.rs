use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use core::fmt::Debug;
use rand::rngs::StdRng;

pub trait Group: Sized + Pairing {
    type BaseField: PrimeField;
    type ScalarField: PrimeField;
    type PreprocessedGroupElement: Clone + Debug;
    type RO: ROTrait<<Self as Group>::BaseField, <Self as Group>::ScalarField>;
    type CE: CommitmentEngineTrait<Self>;
}
pub trait ROConstantsTrait<BaseField> {
    /// produces constants/parameters associated with the hash function
    fn new(rate: usize) -> Self;
}

pub trait ROTrait<BaseField, ScalarField> {
    type Constants: ROConstantsTrait<BaseField> + Clone;

    /// Initializes the hash function
    fn new(constants: Self::Constants) -> Self;

    /// Adds a scalar to the internal state
    fn absorb(&mut self, e: BaseField);

    /// Returns a challenge of `num_bits` by hashing the internal state
    fn squeeze(&mut self) -> ScalarField;
}

pub trait CommitmentEngineTrait<G: Group> {
    /// Holds the type of the commitment key
    type CommitmentKey: Clone + Debug;

    /// Holds the type of the commitment
    type Commitment: Clone + Debug + PartialEq + Eq;

    /// Samples a new commitment key of a specified size
    fn setup(rng: &mut StdRng, degree: usize) -> Self::CommitmentKey;

    /// Commits to the provided vector using the provided generators
    fn commit(ck: &Self::CommitmentKey, v: &[<G as Pairing>::ScalarField]) -> Self::Commitment;
}

// pub trait CommitmentTrait<E: Group>: Clone + Debug + PartialEq + Eq {}
