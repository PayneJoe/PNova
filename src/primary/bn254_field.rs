//// configurations for bn254 curve/field
use crate::poseidon::poseidon_constants::{PoseidonDefaultConfig, PoseidonDefaultConfigEntry};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{fields::models::*, MontBackend, MontConfig, PrimeField};

/// for bn254 base field Fq
#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
pub struct FqBackend;

type FqConfig = MontBackend<FqBackend, 4>;
pub type Fq = Fp256<FqConfig>;

impl PoseidonDefaultConfig<4> for FqConfig {
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

/// for bn254 scalar field Fr
#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "2"]
pub struct FrBackend;

type FrConfig = MontBackend<FrBackend, 4>;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

impl PoseidonDefaultConfig<4> for FrConfig {
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
