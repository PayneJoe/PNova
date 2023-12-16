/// Non-interactive Folding Scheme based Plonkish Nova over BN254 curve
///
///
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, BigInteger};
use ark_ff::{Field, PrimeField};
use jf_primitives::pcs::prelude::Commitment;

use std::marker::PhantomData;

use super::bn254_field::Fq;
use super::plonk::{
    CommitmentKey, PLONKInstance, PLONKShape, PLONKWitness, RelaxedPLONKInstance,
    RelaxedPLONKWitness,
};
use crate::error::MyError;
use crate::poseidon::poseidon_constants::PoseidonDefaultConfigField;

pub struct NIFS<E: Pairing> {
    pub(crate) comm_T: Commitment<E>,
    _p: PhantomData<E>,
}

impl<E: Pairing> NIFS<E> {
    pub fn prove(
        ck: &CommitmentKey<E>,
        pp_digest: &E::ScalarField,
        S: &PLONKShape<E>,
        U1: &RelaxedPLONKInstance<E>,
        W1: &RelaxedPLONKWitness<E>,
        U2: &PLONKInstance<E>,
        W2: &PLONKWitness<E>,
    ) -> Result<(NIFS<E>, (RelaxedPLONKInstance<E>, RelaxedPLONKWitness<E>)), MyError> {
        let sponge_constant = Fq::get_default_poseidon_parameters(3, false).unwrap();
        let mut sponge = PoseidonSponge::<Fq>::new(&sponge_constant);
        todo!()
    }
    pub fn verifiy(
        &self,
        pp_digest: &E::ScalarField,
        U1: &RelaxedPLONKInstance<E>,
        U2: &PLONKInstance<E>,
    ) -> Result<RelaxedPLONKInstance<E>, MyError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::pairing::Pairing;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use jf_primitives::pcs::{
        prelude::{UnivariateKzgPCS, UnivariateUniversalParams},
        PolynomialCommitmentScheme, StructuredReferenceString,
    };

    use crate::primary::kzg::gen_srs_for_testing;
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
        assert!(comm == comm, "");
    }
    #[test]
    fn test_pcs() {
        test_pcs_end_to_end_template::<Bn254>();
    }
}
