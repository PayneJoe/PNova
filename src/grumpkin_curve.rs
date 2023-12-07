////////////////////////////////////////////////////////////// grumpkin curve implementation for cycle fold
// for from_uniform_bytes
use ff::FromUniformBytes;
use halo2curves::grumpkin::{
    Fq as GrumpkinBase, Fr as GrumpkinScalar, G1Affine as GrumpkinAffine,
    G1Compressed as GrumpkinCompressed, G1 as GrumpkinPoint,
};
use num_bigint::BigInt;
// for from_bytes
use pasta_curves::group::GroupEncoding;

use crate::group::{CompressedGroup, Group, PrimeFieldExt};
use crate::keccak_transcript::Keccak256Transcript;

impl Group for GrumpkinPoint {
    type Base = GrumpkinBase;
    type Scalar = GrumpkinScalar;
    type CompressedGroupElement = GrumpkinCompressed;
    type PreprocessedGroupElement = GrumpkinAffine;
    // type RO = PoseidonRO<Self::Base, Self::Scalar>;
    type TE = Keccak256Transcript<Self>;

    fn vartime_multiscalar_mul(
        scalars: &[Self::Scalar],
        bases: &[Self::PreprocessedGroupElement],
    ) -> Self {
        todo!()
    }

    /// Compresses the group element, (x, y) -> (x, sign)
    fn compress(&self) -> Self::CompressedGroupElement {
        todo!()
    }

    /// Produces a preprocessed element
    fn preprocessed(&self) -> Self::PreprocessedGroupElement {
        todo!()
    }

    /// generate n points using a static label string
    fn from_label(label: &'static [u8], n: usize) -> Vec<Self::PreprocessedGroupElement> {
        todo!()
    }

    /// Returns the affine coordinates (x, y, infinty) for the point
    fn to_coordinates(&self) -> (Self::Base, Self::Base, bool) {
        todo!()
    }

    /// Returns an element that is the additive identity of the group
    fn zero() -> Self {
        todo!()
    }

    /// Returns the generator of the group
    fn get_generator() -> Self {
        todo!()
    }

    /// Returns A, B, and the order of the group as a big integer
    fn get_curve_params() -> (Self::Base, Self::Base, BigInt) {
        todo!()
    }
}

impl PrimeFieldExt for GrumpkinScalar {
    fn from_uniform(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 64);
        let bytes_arr: [u8; 64] = bytes[0..64].try_into().unwrap();
        // from_uniform_bytes comes from trait ff::FromUniformBytes
        // from_uniform_bytes -> impl ff::FromUniformBytes for GrumpkinPoint
        GrumpkinScalar::from_uniform_bytes(&bytes_arr)
    }
}

impl CompressedGroup for GrumpkinCompressed {
    type GroupElement = GrumpkinPoint;
    fn decompress(&self) -> Option<Self::GroupElement> {
        // from_bytes comes from trait pasta_curves::group::GroupEncoding
        // from_bytes -> impl pasta_curves::group::GroupEncoding for GrumpkinPoint
        Some(GrumpkinPoint::from_bytes(&self).unwrap())
    }
}
