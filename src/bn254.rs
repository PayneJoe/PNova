//// configurations for bn254 curve/field
use crate::poseidon::{PoseidonDefaultConfig, PoseidonDefaultConfigEntry};
use ark_ff::{fields::models::*, MontBackend, MontConfig};

/// for bn254 Fq
#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
pub struct Bn254FqBackend;

type Bn254FqConfig = MontBackend<Bn254FqBackend, 4>;
pub type Bn254Fq = Fp256<Bn254FqConfig>;

impl PoseidonDefaultConfig<4> for Bn254FqConfig {
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
