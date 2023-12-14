use ark_ec::pairing::Pairing;
use rand::rngs::StdRng;
// use ark_ff::PrimeField;

// pub trait Group: Sized {
//     type BaseField: PrimeField;
//     type ScalarField: PrimeField;
//     type RO: ROTrait<Self::BaseField, Self::ScalarField>;
//     type CE: CommitmentEngineTrait<Self>;
// }
pub trait ROConstantsTrait<BaseField> {
    /// produces constants/parameters associated with the hash function
    fn new(rate: usize) -> Self;
}

pub trait ROTrait<BaseField, ScalarField> {
    type Constants: ROConstantsTrait<BaseField>;

    /// Initializes the hash function
    fn new(constants: Self::Constants) -> Self;

    /// Adds a scalar to the internal state
    fn absorb(&mut self, e: BaseField);

    /// Returns a challenge of `num_bits` by hashing the internal state
    fn squeeze(&mut self) -> ScalarField;
}

pub trait CommitmentEngineTrait<E: Pairing> {
    /// Holds the type of the commitment key
    type CommitmentKey;

    /// Holds the type of the commitment
    type Commitment: CommitmentTrait<E>;

    /// Samples a new commitment key of a specified size
    fn setup(rng: &mut StdRng, degree: usize) -> Self::CommitmentKey;

    /// Commits to the provided vector using the provided generators
    fn commit(ck: &Self::CommitmentKey, v: &[E::ScalarField]) -> Self::Commitment;
}

pub trait CommitmentTrait<E: Pairing> {}
