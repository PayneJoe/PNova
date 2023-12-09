use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{
    end_timer,
    rand::{CryptoRng, RngCore},
    start_timer, vec, One, UniformRand,
};

use jf_primitives::pcs::{
    prelude::{PCSError, UnivariateKzgPCS, UnivariateUniversalParams},
    PolynomialCommitmentScheme, StructuredReferenceString,
};

pub(crate) fn gen_srs_for_testing<E: Pairing, R: RngCore + CryptoRng>(
    rng: &mut R,
    prover_degree: usize,
    verifier_degree: usize,
) -> Result<UnivariateUniversalParams<E>, PCSError> {
    let setup_time = start_timer!(|| ark_std::format!(
        "KZG10::Setup with prover degree {} and verifier degree {}",
        prover_degree,
        verifier_degree
    ));
    let beta = E::ScalarField::rand(rng);
    let g = E::G1::rand(rng);
    let h = E::G2::rand(rng);

    let mut powers_of_beta = vec![E::ScalarField::one()];

    let mut cur = beta;
    let max_degree = ark_std::cmp::max(prover_degree, verifier_degree);
    for _ in 0..max_degree {
        powers_of_beta.push(cur);
        cur *= &beta;
    }

    let window_size = FixedBase::get_mul_window_size(prover_degree + 1);

    let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
    let g_time = start_timer!(|| "Generating powers of G");
    // TODO: parallelization
    let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
    let powers_of_g = FixedBase::msm::<E::G1>(scalar_bits, window_size, &g_table, &powers_of_beta);
    end_timer!(g_time);

    let powers_of_g = E::G1::normalize_batch(&powers_of_g);

    let h = h.into_affine();
    let beta_h = (h * beta).into_affine();

    let powers_of_h = powers_of_beta
        .iter()
        .take(verifier_degree + 1)
        .map(|x| (h * x).into_affine())
        .collect();

    let pp = UnivariateUniversalParams {
        powers_of_g,
        h,
        beta_h,
        powers_of_h,
    };
    end_timer!(setup_time);
    Ok(pp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use jf_utils::test_rng;

    fn test_pcs_end_to_end_template<E>()
    where
        E: Pairing,
    {
        let degree = 4;
        let rng = &mut test_rng();
        let pp: UnivariateUniversalParams<E> = gen_srs_for_testing(rng, degree, 1).unwrap();
        let (ck, _) = pp.trim(degree).unwrap();
        let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
            degree, rng,
        );
        let comm = UnivariateKzgPCS::<E>::commit(&ck, &p).unwrap();
    }

    #[test]
    fn test_pcs() {
        test_pcs_end_to_end_template::<Bn254>();
    }
}
