use crate::poseidon::poseidon_constants::{PoseidonDefaultConfig, PoseidonDefaultConfigEntry};
use crate::provider::{kzg::CommitmentEngine, poseidon::PoseidonRO};
use crate::traits::Group;
use ark_bn254::{Bn254, Fq, FqConfig, Fr, G1Affine};
use ark_ff::fields::MontBackend;

impl PoseidonDefaultConfig<4> for MontBackend<FqConfig, 4> {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultConfigEntry; 7] = [
        PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
        PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
        PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
        PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
    ];
    const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultConfigEntry; 7] = [
        PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
        PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
    ];
}

impl Group for Bn254 {
    type BaseField = Fq;
    type ScalarField = Fr;
    type PreprocessedGroupElement = G1Affine;
    type RO = PoseidonRO<Fq, Fr>;
    type CE = CommitmentEngine<Self>;
}
