pub mod circuit;
pub mod errors;
pub mod nifs;
pub mod plonk;
pub mod traits;

use crate::traits::{
    commitment::{CommitmentEngineTrait, CommitmentTrait},
    Group,
};

type CommitmentKey<G> = <<G as traits::Group>::CE as CommitmentEngineTrait<G>>::CommitmentKey;
type Commitment<G> = <<G as Group>::CE as CommitmentEngineTrait<G>>::Commitment;
type CompressedCommitment<G> = <<<G as Group>::CE as CommitmentEngineTrait<G>>::Commitment as CommitmentTrait<G>>::CompressedCommitment;
type CE<G> = <G as Group>::CE;
