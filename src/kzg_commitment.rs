use core::{
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, MulAssign},
};
use ff::Field;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use crate::{
    commitment::{AbsorbInROTrait, CommitmentEngineTrait, CommitmentTrait},
    error::MyError,
    group::{CompressedGroup, Group},
    ro::ROTrait,
    transcript::TranscriptReprTrait,
};

/// this is so-called ck for the purpose of commitment, a type that holds commitment generators (points)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentKey<G: Group> {
    ck: Vec<G::PreprocessedGroupElement>,
    _p: PhantomData<G>,
}

/// A type that holds a commitment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Commitment<G: Group> {
    pub(crate) comm: G,
}

/////////////////////////////////////////////// Mul/MulAssign ops
/// com_a *= b
impl<G: Group> MulAssign<G::Scalar> for Commitment<G> {
    fn mul_assign(&mut self, scalar: G::Scalar) {
        let result = (self as &Commitment<G>).comm * scalar;
        *self = Commitment { comm: result };
    }
}

/// com_a * b
impl<G: Group> Mul<G::Scalar> for Commitment<G> {
    type Output = Commitment<G>;

    fn mul(self, scalar: G::Scalar) -> Commitment<G> {
        Commitment {
            comm: self.comm * scalar,
        }
    }
}

/// &com_a * &b
impl<'a, 'b, G: Group> Mul<&'b G::Scalar> for &'a Commitment<G> {
    type Output = Commitment<G>;
    fn mul(self, scalar: &'b G::Scalar) -> Commitment<G> {
        Commitment {
            comm: self.comm * scalar,
        }
    }
}

///////////////////////////////////////////// Add/AddAssign ops
/// com_a += &com_b
impl<'b, G: Group> AddAssign<&'b Commitment<G>> for Commitment<G> {
    fn add_assign(&mut self, other: &'b Commitment<G>) {
        let result = (self as &Commitment<G>).comm + other.comm;
        *self = Commitment { comm: result };
    }
}

/// com_a += com_b
impl<G: Group> AddAssign<Commitment<G>> for Commitment<G> {
    fn add_assign(&mut self, other: Commitment<G>) {
        *self += &other;
    }
}

/// com_a + &com_b -> &com_a + &com_b
impl<'b, G: Group> Add<&'b Commitment<G>> for Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, rhs: &'b Commitment<G>) -> Self::Output {
        &self + rhs
    }
}

/// com_a + com_b -> &com_a + com_b
impl<G: Group> Add<Commitment<G>> for Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, rhs: Commitment<G>) -> Self::Output {
        &self + rhs
    }
}

/// &com_a + &com_b
impl<'a, 'b, G: Group> Add<&'b Commitment<G>> for &'a Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, other: &'b Commitment<G>) -> Commitment<G> {
        Commitment {
            comm: self.comm + other.comm,
        }
    }
}

/// &com_a + com_b -> &com_a + &com_b
impl<'a, G: Group> Add<Commitment<G>> for &'a Commitment<G> {
    type Output = Commitment<G>;
    fn add(self, other: Commitment<G>) -> Self::Output {
        self + &other
    }
}

/// A type that holds a compressed commitment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CompressedCommitment<G: Group> {
    comm: G::CompressedGroupElement,
}

/// convert compressed commitment into bytes array, involving one base field
impl<G: Group> TranscriptReprTrait<G> for CompressedCommitment<G> {
    fn to_transcript_bytes(&self) -> Vec<u8> {
        self.comm.to_transcript_bytes()
    }
}

/// absort commitment into ro, involving three base fields
impl<G: Group> AbsorbInROTrait<G> for Commitment<G> {
    fn absorb_in_ro(&self, ro: &mut G::RO) {
        let (x, y, is_infinity) = self.comm.to_coordinates();
        ro.absorb(x);
        ro.absorb(y);
        ro.absorb(if is_infinity {
            G::Base::ONE
        } else {
            G::Base::ZERO
        });
    }
}

/// convert commitment into btyes array, involving three base field
impl<G: Group> TranscriptReprTrait<G> for Commitment<G> {
    fn to_transcript_bytes(&self) -> Vec<u8> {
        let (x, y, is_infinity) = self.comm.to_coordinates();
        let is_infinity_byte = (!is_infinity).into();
        [
            x.to_transcript_bytes(),
            y.to_transcript_bytes(),
            [is_infinity_byte].to_vec(),
        ]
        .concat()
    }
}

/// default commitment with group zero
impl<G: Group> Default for Commitment<G> {
    fn default() -> Self {
        Commitment { comm: G::zero() }
    }
}

impl<G: Group> CommitmentTrait<G> for Commitment<G> {
    type CompressedCommitment = CompressedCommitment<G>;

    fn compress(&self) -> Self::CompressedCommitment {
        CompressedCommitment {
            comm: self.comm.compress(),
        }
    }

    fn to_coordinates(&self) -> (G::Base, G::Base, bool) {
        self.comm.to_coordinates()
    }

    fn decompress(c: &Self::CompressedCommitment) -> Result<Self, MyError> {
        let comm = c.comm.decompress();
        if comm.is_none() {
            return Err(MyError::CommitmentError);
        }
        Ok(Commitment {
            comm: comm.unwrap(),
        })
    }
}

/// Provides a commitment engine
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KZGCommitmentEngine<G: Group> {
    _p: PhantomData<G>,
}

impl<G: Group> CommitmentEngineTrait<G> for KZGCommitmentEngine<G> {
    // commitment key is also called proving key, while the verifying key is not needed on prover side
    type CommitmentKey = CommitmentKey<G>;
    type Commitment = Commitment<G>;

    /// universal setup for testing
    /// trusted setup for production
    fn setup(label: &'static [u8], n: usize) -> Self::CommitmentKey {
        todo!()
        // Self::CommitmentKey {
        //     ck: G::from_label(label, n.next_power_of_two()),
        //     _p: Default::default(),
        // }
    }

    fn commit(ck: &Self::CommitmentKey, v: &[G::Scalar]) -> Self::Commitment {
        assert!(ck.ck.len() >= v.len());
        Commitment {
            comm: G::vartime_multiscalar_mul(v, &ck.ck[..v.len()]),
        }
    }
}
