pub mod bn256_grumpkin;
pub mod keccak;
pub mod kzg;
pub mod poseidon;

use ff::PrimeField;
use pasta_curves::{self, arithmetic::CurveAffine, group::Group as AnotherGroup};

// TODO
pub(crate) fn cpu_best_multiexp<C: CurveAffine>(coeffs: &[C::Scalar], bases: &[C]) -> C::Curve {
    C::Curve::identity()
}
