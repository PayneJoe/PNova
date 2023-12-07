/////////////////////////////////////////////////////////////// bn256 curve implementation for cycle fold
// for from_uniform_bytes
use ff::FromUniformBytes;
use halo2curves::bn256::{
    Fq as Bn256Base, Fr as Bn256Scalar, G1Affine as Bn256Affine, G1Compressed as Bn256Compressed,
    G1 as Bn256Point,
};
// for to_affine/coordinates/identity/from_bytes/to_bytes/generator
use num_bigint::BigInt;
use num_traits::Num;
use pasta_curves::{
    arithmetic::{CurveAffine, CurveExt},
    group::cofactor::CofactorCurveAffine,
    group::{Curve, Group as AnotherGroup, GroupEncoding},
};
// sha3 related
use digest::{ExtendableOutput, Update};
use sha3::Shake256;
use std::io::Read;
// rayon
use rayon::prelude::*;

// local libs
use crate::{
    exponentiation::*,
    group::{CompressedGroup, Group, PrimeFieldExt},
    keccak_transcript::Keccak256Transcript,
    poseidon_ro::PoseidonRO,
    transcript::TranscriptReprTrait,
};

impl Group for Bn256Point {
    type Base = Bn256Base;
    type Scalar = Bn256Scalar;
    type CompressedGroupElement = Bn256Compressed;
    type PreprocessedGroupElement = Bn256Affine;
    type RO = PoseidonRO<Self::Base, Self::Scalar>;
    type TE = Keccak256Transcript<Self>;

    fn vartime_multiscalar_mul(
        scalars: &[Self::Scalar],
        bases: &[Self::PreprocessedGroupElement],
    ) -> Self {
        cpu_best_multiexp(scalars, bases)
    }

    /// Compresses the group element, (x, y) -> (x, sign)
    fn compress(&self) -> Self::CompressedGroupElement {
        self.to_bytes()
    }

    /// converting projective representation into affine point
    fn preprocessed(&self) -> Self::PreprocessedGroupElement {
        self.to_affine()
    }

    /// generate n randomized points using shake256 hash
    fn from_label(label: &'static [u8], n: usize) -> Vec<Self::PreprocessedGroupElement> {
        let mut shake = Shake256::default();
        shake.update(label);
        let mut reader = shake.finalize_xof();
        let mut uniform_bytes_vec = Vec::new();
        for _ in 0..n {
            let mut uniform_bytes = [0u8; 32];
            reader.read_exact(&mut uniform_bytes).unwrap();
            uniform_bytes_vec.push(uniform_bytes);
        }
        let gens_proj: Vec<Self> = (0..n)
            .collect::<Vec<usize>>()
            .into_par_iter()
            .map(|i| {
                let hash = Self::hash_to_curve("from_uniform_bytes");
                hash(&uniform_bytes_vec[i])
            })
            .collect();

        let num_threads = rayon::current_num_threads();
        if gens_proj.len() > num_threads {
            let chunk = (gens_proj.len() as f64 / num_threads as f64).ceil() as usize;
            (0..num_threads)
                .collect::<Vec<usize>>()
                .into_par_iter()
                .map(|i| {
                    let start = i * chunk;
                    let end = if i == num_threads - 1 {
                        gens_proj.len()
                    } else {
                        core::cmp::min((i + 1) * chunk, gens_proj.len())
                    };
                    if end > start {
                        let mut gens = vec![Bn256Affine::identity(); end - start];
                        <Self as Curve>::batch_normalize(&gens_proj[start..end], &mut gens);
                        gens
                    } else {
                        vec![]
                    }
                })
                .collect::<Vec<Vec<Bn256Affine>>>()
                .into_par_iter()
                .flatten()
                .collect()
        } else {
            let mut gens = vec![Bn256Affine::identity(); n];
            <Self as Curve>::batch_normalize(&gens_proj, &mut gens);
            gens
        }
    }

    /// Returns the affine coordinates (x, y, infinty) for the point
    fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
        let coordinates = self.to_affine().coordinates();
        if coordinates.is_some().unwrap_u8() == 1
          // The bn256/grumpkin convention is to define and return the identity point's affine encoding (not None)
          && (Self::PreprocessedGroupElement::identity() != self.to_affine())
        {
            (*coordinates.unwrap().x(), *coordinates.unwrap().y(), false)
        } else {
            (Self::Base::zero(), Self::Base::zero(), true)
        }
    }

    /// Returns an element that is the additive identity of the group
    fn zero() -> Self {
        Self::identity()
    }

    /// Returns the generator of the group
    fn get_generator() -> Self {
        Self::generator()
    }

    /// Returns A, B, and the order of the group as a big integer
    fn get_curve_params() -> (Self::Base, Self::Base, BigInt) {
        let A = Self::a();
        let B = Self::b();
        let order = BigInt::from_str_radix(
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
            16,
        )
        .unwrap();

        (A, B, order)
    }
}

impl PrimeFieldExt for Bn256Scalar {
    fn from_uniform(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 64);
        let bytes_arr: [u8; 64] = bytes[0..64].try_into().unwrap();
        // from_uniform_bytes comes from trait ff::FromUniformBytes
        // from_uniform_bytes -> impl ff::FromUniformBytes for Bn256Point
        Bn256Scalar::from_uniform_bytes(&bytes_arr)
    }
}

impl CompressedGroup for Bn256Compressed {
    type GroupElement = Bn256Point;
    fn decompress(&self) -> Option<Self::GroupElement> {
        // from_bytes comes from trait pasta_curves::group::GroupEncoding
        // from_bytes -> impl pasta_curves::group::GroupEncoding for Bn256Point
        Some(Bn256Point::from_bytes(&self).unwrap())
    }
}

impl<G: Group> TranscriptReprTrait<G> for Bn256Compressed {
    fn to_transcript_bytes(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
}
