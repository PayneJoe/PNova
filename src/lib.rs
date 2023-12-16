pub mod error;
pub mod nifs;
pub mod plonk;
pub mod poseidon;
pub mod primary;
pub mod provider;
pub mod secondary;
pub mod traits;

type Commitment<G> = <<G as traits::Group>::CE as traits::CommitmentEngineTrait<G>>::Commitment;
type CommitmentKey<G> =
    <<G as traits::Group>::CE as traits::CommitmentEngineTrait<G>>::CommitmentKey;
