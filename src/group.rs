/// standard lib
use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

// third-party lib
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

// custom defined lib
use crate::{error::MyError, transcript::TranscriptEngineTrait};

/////////////////////////////////////////// PrimeField for scalar field
/// truncate input bytes into fixed length bytes array before converting to PrimeField if necessary
pub trait PrimeFieldExt: PrimeField {
    /// Returns a scalar representing the bytes
    fn from_uniform(bytes: &[u8]) -> Self;
}

/////////////////////////////////////////// group operation traits
/// basic marker trait for Add/AddAssign/Sub/SubAssign
/// a + b, a += b, a - b, a -= b
pub trait GroupOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}

/// marker trait for Mul/MulAssign
/// a * b, a *= b
pub trait ScalarMul<Rhs, Output = Self>: Mul<Rhs, Output = Output> + MulAssign<Rhs> {}

/// a + &b, a += &b, a - &b, a -= &b
pub trait GroupOpsOwned<Rhs = Self, Output = Self>: for<'r> GroupOps<&'r Rhs, Output> {}
/// a * &b, a *= &b
pub trait ScalarMulOwned<Rhs, Output = Self>: for<'r> ScalarMul<&'r Rhs, Output> {}

////////////////////////////////////////////  impl ops trait for any type T with Add/Sub/AddAssign/SubAssign/Mul/MulAssign implemented
impl<T, Rhs, Output> GroupOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + AddAssign<Rhs> + SubAssign<Rhs>
{
}
impl<T, Rhs, Output> ScalarMul<Rhs, Output> for T where T: Mul<Rhs, Output = Output> + MulAssign<Rhs>
{}

///////////////////////////////////////////  impl ops trait where right part is a reference for any type T with Add/Sub/AddAssign/SubAssign/Mul/MulAssign references implemented
impl<T, Rhs, Output> GroupOpsOwned<Rhs, Output> for T where T: for<'r> GroupOps<&'r Rhs, Output> {}
impl<T, Rhs, Output> ScalarMulOwned<Rhs, Output> for T where T: for<'r> ScalarMul<&'r Rhs, Output> {}

/////////////////////////////////////////// compressed point
/// output x-coordinate along with the sign y-coordinate provided a AffinePoint (x, y)
pub trait CompressedGroup:
    Copy + Clone + Debug + Eq + Sized + Serialize + for<'de> Deserialize<'de>
{
    /// A type that holds the decompressed version of the compressed group element
    type GroupElement: Group + Serialize + for<'de> Deserialize<'de>;

    /// Decompresses the compressed group element
    fn decompress(&self) -> Option<Self::GroupElement>;
}

////////////////////////////////////////// uncompressed point
pub trait Group:
    Copy
    + Clone
    + Debug
    + Eq
    + Sized
    + GroupOps
    + GroupOpsOwned
    + ScalarMul<Self::Scalar>
    + ScalarMulOwned<Self::Scalar>
    + Serialize
    + for<'de> Deserialize<'de>
{
    // field type: inner type representing scalar field of group element (#E(Fp))
    type Scalar: PrimeFieldExt + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>;

    // field type: inner type representing base field of group element (Fp)
    type Base: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>;

    // point type: inner type representing compressed group element (E(Fp))
    type CompressedGroupElement: CompressedGroup<GroupElement = Self>;

    // point type: inner type representing preprocessed group element (E(Fp))
    type PreprocessedGroupElement: Clone + Debug + Serialize + for<'de> Deserialize<'de>;

    // hash type: inner type representing hasher for the purpose of folding factor (#E(Fp))
    // type RO: ROTrait<Self::Base, Self::Scalar> + Serialize + for<'de> Deserialize<'de>;

    // hash type: inner type representing hasher for Fiat-Shamir transcript
    type TE: TranscriptEngineTrait<Self>;

    // pcs type: inner type representing commitment scheme
    // type CE: CommitmentEngineTrait<Self> + Serialize + for<'de> Deserialize<'de>;

    // multiexponentiation
    // [s_1]b_1, [s_2]b_2, [s_3]b_3, ...
    fn vartime_multiscalar_mul(
        scalars: &[Self::Scalar],
        bases: &[Self::PreprocessedGroupElement],
    ) -> Self;

    /// Compresses the group element, (x, y) -> (x, sign)
    fn compress(&self) -> Self::CompressedGroupElement;

    /// Produces a preprocessed element
    fn preprocessed(&self) -> Self::PreprocessedGroupElement;

    /// generate n points using a static label string
    fn from_label(label: &'static [u8], n: usize) -> Vec<Self::PreprocessedGroupElement>;

    /// Returns the affine coordinates (x, y, infinty) for the point
    fn to_coordinates(&self) -> (Self::Base, Self::Base, bool);

    /// Returns an element that is the additive identity of the group
    fn zero() -> Self;

    /// Returns the generator of the group
    fn get_generator() -> Self;

    /// Returns A, B, and the order of the group as a big integer
    fn get_curve_params() -> (Self::Base, Self::Base, BigInt);
}
