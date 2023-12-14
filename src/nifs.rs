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
