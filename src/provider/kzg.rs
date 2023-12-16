use rand::rngs::StdRng;
use std::marker::PhantomData;

use crate::traits::CommitmentEngineTrait;

use ark_ec::{pairing::Pairing, scalar_mul::fixed_base::FixedBase, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{
    end_timer,
    rand::{CryptoRng, RngCore},
    start_timer, vec, One, UniformRand,
};

use jf_primitives::pcs::prelude::Commitment;
use jf_primitives::pcs::{
    prelude::{PCSError, UnivariateKzgPCS, UnivariateProverParam, UnivariateUniversalParams},
    PolynomialCommitmentScheme, StructuredReferenceString,
};

use crate::traits::Group;

pub fn gen_srs_for_testing<E: Pairing, R: RngCore + CryptoRng>(
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

/// implement LOCAL trait CommitmentEngineTrait for it
///
pub struct CommitmentEngine<G: Group> {
    _p: PhantomData<G>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZGCommitmentKey<G: Pairing>(UnivariateProverParam<G>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZGCommitment<G: Pairing>(Commitment<G>);

// impl<G> CommitmentTrait<G> for KZGCommitment<G> where G: Group {}

impl<G> CommitmentEngineTrait<G> for CommitmentEngine<G>
where
    G: Group,
{
    type CommitmentKey = KZGCommitmentKey<G>;
    type Commitment = KZGCommitment<G>;

    fn setup(rng: &mut StdRng, degree: usize) -> Self::CommitmentKey {
        let pp: UnivariateUniversalParams<G> = gen_srs_for_testing(rng, degree, 1).unwrap();
        let (ck, _) = pp.trim(degree).unwrap();
        KZGCommitmentKey(ck)
    }

    fn commit(ck: &Self::CommitmentKey, v: &[<G as Pairing>::ScalarField]) -> Self::Commitment {
        let poly = <DensePolynomial<<G as Pairing>::ScalarField> as DenseUVPolynomial<
            <G as Pairing>::ScalarField,
        >>::from_coefficients_vec(v.to_vec());
        KZGCommitment(UnivariateKzgPCS::<G>::commit(&ck.0, &poly).unwrap())
    }
}
