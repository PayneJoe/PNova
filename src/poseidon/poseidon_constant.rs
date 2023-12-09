use crate::poseidon::grain_lfsr::PoseidonGrainLFSR;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{fields::models::*, FpConfig, PrimeField};
use ark_std::{vec, vec::Vec};

/// An entry in the default Poseidon parameters
pub struct PoseidonDefaultConfigEntry {
    /// The rate (in terms of number of field elements).
    pub rate: usize,
    /// Exponent used in S-boxes.
    pub alpha: usize,
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Number of matrices to skip when generating parameters using the Grain LFSR.
    ///
    /// The matrices being skipped are those that do not satisfy all the desired properties.
    /// See the [reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage) for more detail.
    pub skip_matrices: usize,
}

impl PoseidonDefaultConfigEntry {
    /// Create an entry in `PoseidonDefaultConfig`.
    pub const fn new(
        rate: usize,
        alpha: usize,
        full_rounds: usize,
        partial_rounds: usize,
        skip_matrices: usize,
    ) -> Self {
        Self {
            rate,
            alpha,
            full_rounds,
            partial_rounds,
            skip_matrices,
        }
    }
}

/// A trait for default Poseidon parameters associated with a prime field
pub trait PoseidonDefaultConfig<const N: usize>: FpConfig<N> {
    /// An array of the parameters optimized for constraints
    /// (rate, alpha, full_rounds, partial_rounds, skip_matrices)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    ///
    /// Here, `skip_matrices` denote how many matrices to skip before
    /// finding one that satisfy all the requirements.
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultConfigEntry; 7];

    /// An array of the parameters optimized for weights
    /// (rate, alpha, full_rounds, partial_rounds, skip_matrices)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultConfigEntry; 7];
}

/// A field with Poseidon parameters associated
pub trait PoseidonDefaultConfigField: PrimeField {
    /// Obtain the default Poseidon parameters for this rate and for this prime field,
    /// with a specific optimization goal.
    fn get_default_poseidon_parameters(
        rate: usize,
        optimized_for_weights: bool,
    ) -> Option<PoseidonConfig<Self>>;
}

/// Internal function that uses the `PoseidonDefaultConfig` to compute the Poseidon parameters.
pub fn get_default_poseidon_parameters_internal<P: PoseidonDefaultConfig<N>, const N: usize>(
    rate: usize,
    optimized_for_weights: bool,
) -> Option<PoseidonConfig<Fp<P, N>>> {
    let params_set = if !optimized_for_weights {
        P::PARAMS_OPT_FOR_CONSTRAINTS
    } else {
        P::PARAMS_OPT_FOR_WEIGHTS
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<Fp<P, N>>(
                Fp::<P, N>::MODULUS_BIT_SIZE as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return Some(PoseidonConfig {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            });
        }
    }

    None
}

/// Internal function that computes the ark and mds from the Poseidon Grain LFSR.
pub fn find_poseidon_ark_and_mds<F: PrimeField>(
    prime_bits: u64,
    rate: usize,
    full_rounds: u64,
    partial_rounds: u64,
    skip_matrices: u64,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    let mut lfsr = PoseidonGrainLFSR::new(
        false,
        prime_bits,
        (rate + 1) as u64,
        full_rounds,
        partial_rounds,
    );

    let mut ark = Vec::<Vec<F>>::with_capacity((full_rounds + partial_rounds) as usize);
    for _ in 0..(full_rounds + partial_rounds) {
        ark.push(lfsr.get_field_elements_rejection_sampling(rate + 1));
    }

    let mut mds = Vec::<Vec<F>>::with_capacity(rate + 1);
    mds.resize(rate + 1, vec![F::zero(); rate + 1]);
    for _ in 0..skip_matrices {
        let _ = lfsr.get_field_elements_mod_p::<F>(2 * (rate + 1));
    }

    // a qualifying matrix must satisfy the following requirements
    // - there is no duplication among the elements in x or y
    // - there is no i and j such that x[i] + y[j] = p
    // - the resultant MDS passes all the three tests

    let xs = lfsr.get_field_elements_mod_p::<F>(rate + 1);
    let ys = lfsr.get_field_elements_mod_p::<F>(rate + 1);

    for i in 0..(rate + 1) {
        for j in 0..(rate + 1) {
            mds[i][j] = (xs[i] + &ys[j]).inverse().unwrap();
        }
    }

    (ark, mds)
}

impl<const N: usize, P: PoseidonDefaultConfig<N>> PoseidonDefaultConfigField for Fp<P, N> {
    fn get_default_poseidon_parameters(
        rate: usize,
        optimized_for_weights: bool,
    ) -> Option<PoseidonConfig<Self>> {
        get_default_poseidon_parameters_internal::<P, N>(rate, optimized_for_weights)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::primary::bn254_field::*;
    use ark_crypto_primitives::sponge::{
        poseidon::PoseidonSponge, CryptographicSponge, FieldBasedCryptographicSponge,
    };
    use ark_ff::MontFp;

    #[test]
    fn test_bn254_fq_params() {
        // 3, 5, 8, 56, 0 is the best option for bn254 base field Fq
        let constraints_rate_3 = Fq::get_default_poseidon_parameters(3, false).unwrap();
        assert_eq!(
            constraints_rate_3.ark[0][0],
            MontFp!(
                "11633431549750490989983886834189948010834808234699737327785600195936805266405"
            )
        );
    }

    #[test]
    fn test_poseidon_end_to_end() {
        let sponge_param = Fq::get_default_poseidon_parameters(3, false).unwrap();

        let mut sponge = PoseidonSponge::<Fq>::new(&sponge_param);
        sponge.absorb(&vec![Fq::from(0u8), Fq::from(1u8), Fq::from(2u8)]);
        let res = sponge.squeeze_native_field_elements(3);
        assert_eq!(
            res[0],
            MontFp!(
                "13505558253904840554372886088574885784502988543966086461233803614170723033622"
            )
        );
        assert_eq!(
            res[1],
            MontFp!("2010393222813830976204503948151039392318660137898235940886459326805089000473")
        );
        assert_eq!(
            res[2],
            MontFp!(
                "14855598803087928644687564007348125840452284810388803200660562111886369342607"
            )
        );
    }
}
