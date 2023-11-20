/// PLONK Instance
///
use crate::errors::NovaError;
use crate::traits::Group;
use crate::Commitment;

// arkworks

use ark_std::marker::PhantomData;

// // jellyfish
// use jf_plonk::{
//     errors::PlonkError,
//     proof_system::{PlonkKzgSnark, UniversalSNARK},
//     transcript::StandardTranscript,
// };
// use jf_primitives::pcs::{
//     prelude::{Commitment, UnivariateKzgPCS, UnivariateUniversalParams},
//     StructuredReferenceString,
// };

// others

use serde::{Deserialize, Serialize};

/// Public parameters for a given PLONK
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONK<G: Group> {
    _p: PhantomData<G>,
}

// A type that holds the shape of the PLONK circuit
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKShape<G>
where
    G: Group,
{
    // number of constrain or gate, row number
    pub(crate) num_cons: usize,
    // number of wire types, column number
    // 5 for TurboPlonk and 6 for UltraPlonk
    pub(crate) num_wire_types: usize,
    // number of public input gate
    pub(crate) num_public_input: usize,

    // PLONK selectors
    pub(crate) q_c: Vec<G::Scalar>,
    // with length 5
    pub(crate) q_lc: Vec<Vec<G::Scalar>>,
    // with length 2
    pub(crate) q_mul: Vec<Vec<G::Scalar>>,
    pub(crate) q_ecc: Vec<G::Scalar>,
    pub(crate) q_hash: Vec<G::Scalar>,
    pub(crate) q_o: Vec<G::Scalar>,
    pub(crate) q_e: Vec<G::Scalar>,
}

/// A type that holds witness vectors for a given PLONK instance
/// The size of wire list is 5 for TurboPlonk, and 6 for UltraPlonk
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKWitness<G>
where
    G: Group,
{
    W: Vec<Vec<G::Scalar>>,
}

/// A type that holds an PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONKInstance<G>
where
    G: Group,
{
    pub(crate) comm_W: Vec<Commitment<G>>,
    pub(crate) X: Vec<G::Scalar>,
}

/// A type that holds a witness for a given Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaxedPLONKWitness<G>
where
    G: Group,
{
    pub(crate) W: Vec<Vec<G::Scalar>>,
    pub(crate) E: Vec<G::Scalar>,
}

/// A type that holds a Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RelaxedPLONKInstance<G>
where
    G: Group,
{
    pub(crate) comm_W: Vec<Commitment<G>>,
    pub(crate) comm_E: Commitment<G>,
    pub(crate) X: Vec<G::Scalar>,
    pub(crate) u: G::Scalar,
}

impl<G> PLONK<G> where G: Group {}

impl<G> PLONKShape<G>
where
    G: Group,
{
    fn new(
        num_cons: usize,
        num_wire_types: usize,
        num_public_input: usize,
        q_c: Vec<G::Scalar>,
        q_lc: Vec<Vec<G::Scalar>>,
        q_mul: Vec<Vec<G::Scalar>>,
        q_ecc: Vec<G::Scalar>,
        q_hash: Vec<G::Scalar>,
        q_o: Vec<G::Scalar>,
        q_e: Vec<G::Scalar>,
    ) -> Result<PLONKShape<G>, NovaError> {
        // ....
        Ok(PLONKShape {
            num_cons,
            num_wire_types,
            num_public_input,
            q_c: q_c.to_owned(),
            q_lc: q_lc.to_owned(),
            q_mul: q_mul.to_owned(),
            q_ecc: q_ecc.to_owned(),
            q_hash: q_hash.to_owned(),
            q_o: q_o.to_owned(),
            q_e: q_e.to_owned(),
        })
    }

    /// Checks if the Relaxed PLONK instance is satisfiable given a witness and its shape
    pub fn is_sat_relaxed(
        &self,
        _ck: G::Scalar, // &CommitmentKey<G>,
        _U: &RelaxedPLONKInstance<G>,
        _W: &RelaxedPLONKWitness<G>,
    ) -> Result<(), NovaError> {
        //
        Ok(())
    }

    /// Checks if the PLONK instance is satisfiable given a witness and its shape
    pub fn is_sat(
        &self,
        _ck: G::Scalar, // &CommitmentKey<G>,
        _U: &PLONKInstance<G>,
        _W: &PLONKWitness<G>,
    ) -> Result<(), NovaError> {
        //
        Ok(())
    }

    /// A method to compute a commitment to the cross-term `T` given a
    /// Relaxed PLONK instance-witness pair and an PLONK instance-witness pair
    pub fn commit_T(
        &self,
        _ck: G::Scalar, // &CommitmentKey<G>,
        _U1: &RelaxedPLONKInstance<G>,
        _W1: &RelaxedPLONKWitness<G>,
        _U2: &PLONKInstance<G>,
        _W2: &PLONKWitness<G>,
    ) -> Result<(Vec<G::Scalar>, Commitment<G>), NovaError> {
        //
        Err(NovaError::TODO)
    }
}

impl<G> PLONKWitness<G>
where
    G: Group,
{
    /// A method to create a witness object using a vector of scalars
    pub fn new(S: &PLONKShape<G>, W: &[Vec<G::Scalar>]) -> Result<PLONKWitness<G>, NovaError> {
        if S.num_wire_types != W.len() {
            Err(NovaError::InvalidNumWireTypes)
        } else {
            Ok(PLONKWitness { W: W.to_owned() })
        }
    }
}

impl<G> PLONKInstance<G> where G: Group {}

impl<G> RelaxedPLONKWitness<G>
where
    G: Group,
{
    /// Folds an incoming PLONKWitness into the current one
    pub fn fold(
        &self,
        W2: &PLONKWitness<G>,
        T: &[G::Scalar],
        r: &G::Scalar,
    ) -> Result<RelaxedPLONKWitness<G>, NovaError> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(NovaError::InvalidNumWireTypes);
        }

        let W = W1
            .iter()
            .zip(W2)
            .map(|(w1, w2)| {
                w1.iter()
                    .zip(w2)
                    .map(|(a, b)| *a + *r * *b)
                    .collect::<Vec<G::Scalar>>()
            })
            .collect();
        let E = E1.iter().zip(T).map(|(a, b)| *a + *r * *b).collect();
        Ok(RelaxedPLONKWitness { W, E })
    }
}

impl<G> RelaxedPLONKInstance<G> where G: Group {}

#[cfg(test)]
mod tests {}
