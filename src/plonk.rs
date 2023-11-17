/// PLONK Instance
///
///
///
///
use crate::errors::NovaError;
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{FftField, Field};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Radix2EvaluationDomain};
use ark_std::{format, marker::PhantomData};

use jf_plonk::{
    errors::PlonkError,
    proof_system::{PlonkKzgSnark, UniversalSNARK},
    transcript::StandardTranscript,
};
use jf_primitives::pcs::{
    prelude::{Commitment, UnivariateKzgPCS, UnivariateUniversalParams},
    StructuredReferenceString,
};

use jf_utils::par_utils::parallelizable_slice_iter;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// Public parameters for a given PLONK
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONK<E, F>
where
    E: Pairing,
    F: FftField,
{
    _p: PhantomData<E>,
}

// A type that holds the shape of the PLONK circuit
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKShape<E, F>
where
    E: Pairing,
    F: FftField,
{
    // number of constrain or gate, row number
    pub(crate) num_cons: usize,
    // number of wire types, column number
    // 5 for TurboPlonk and 6 for UltraPlonk
    pub(crate) num_wire_types: usize,
    // number of public input gate
    pub(crate) num_public_input: usize,

    // PLONK selectors
    pub(crate) q_c: Vec<E::ScalarField>,
    // with length 5
    pub(crate) q_lc: Vec<Vec<E::ScalarField>>,
    // with length 2
    pub(crate) q_mul: Vec<Vec<E::ScalarField>>,
    pub(crate) q_ecc: Vec<E::ScalarField>,
    pub(crate) q_hash: Vec<E::ScalarField>,
    pub(crate) q_o: Vec<E::ScalarField>,
    pub(crate) q_e: Vec<E::ScalarField>,
    // polynomial evaluation domain
    // pub(crate) eval_domain: Radix2EvaluationDomain<F>,
}

/// A type that holds witness vectors for a given PLONK instance
/// The size of wire list is 5 for TurboPlonk, and 6 for UltraPlonk
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKWitness<E, F>
where
    E: Pairing,
    F: FftField,
{
    W: Vec<Vec<E::ScalarField>>,
}

/// A type that holds an PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONKInstance<E, F>
where
    E: Pairing,
    F: FftField,
{
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) X: Vec<E::ScalarField>,
}

/// A type that holds a witness for a given Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaxedPLONKWitness<E, F>
where
    E: Pairing,
    F: FftField,
{
    pub(crate) W: Vec<Vec<E::ScalarField>>,
    pub(crate) E: Vec<E::ScalarField>,
}

/// A type that holds a Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RelaxedPLONKInstance<E, F>
where
    E: Pairing,
    F: FftField,
{
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) comm_E: Commitment<E>,
    pub(crate) X: Vec<E::ScalarField>,
    pub(crate) u: E::ScalarField,
}

impl<E, F> PLONK<E, F>
where
    E: Pairing,
    F: FftField,
{
    type CommitmentKey = UnivariateUniversalParams<E>;
    /// Samples public parameters for the specified number of constraints and variables in an PLONK
    pub fn commitment_key(S: &PLONKShape<E>) -> UnivariateUniversalParams<E> {
        let srs_size = S.num_cons;
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        let srs = PlonkKzgSnark::<Bls12_381>::universal_setup(srs_size, &mut rng)?;
        let (commit_key, _) = srs.trim(srs_size);
        commit_key
    }

    /// Evaluation domain for polynomials
    pub fn evaluation_domain(S: &PLONKShape<E>) -> Radix2EvaluationDomain<F> {
        let domain = Radix2EvaluationDomain::<E::ScalarField>::new(S.num_cons)
            .ok_or(PlonkError::DomainCreationError)?;
        domain
    }
}

impl<E, F> PLONKShape<E, F>
where
    E: Pairing,
    F: FftField,
{
    fn new(
        num_cons: usize,
        num_wire_types: usize,
        num_public_input: usize,
        q_c: Vec<E::ScalarField>,
        q_lc: Vec<Vec<E::ScalarField>>,
        q_mul: Vec<Vec<E::ScalarField>>,
        q_ecc: Vec<E::ScalarField>,
        q_hash: Vec<E::ScalarField>,
        q_o: Vec<E::ScalarField>,
        q_e: Vec<E::ScalarField>,
    ) -> Result<PLONKShape<E>, NovaError> {
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
        ck: E::ScalarField, // &CommitmentKey<E>,
        U: &RelaxedPLONKInstance<E>,
        W: &RelaxedPLONKWitness<E>,
    ) -> Result<(), NovaError> {
        //
        Ok(())
    }

    /// Checks if the PLONK instance is satisfiable given a witness and its shape
    pub fn is_sat(
        &self,
        ck: E::ScalarField, // &CommitmentKey<E>,
        U: &PLONKInstance<E>,
        W: &PLONKWitness<E>,
    ) -> Result<(), NovaError> {
        //
        Ok(())
    }

    /// A method to compute a commitment to the cross-term `T` given a
    /// Relaxed PLONK instance-witness pair and an PLONK instance-witness pair
    pub fn commit_T(
        &self,
        ck: E::ScalarField, // &CommitmentKey<E>,
        U1: &RelaxedPLONKInstance<E>,
        W1: &RelaxedPLONKWitness<E>,
        U2: &PLONKInstance<E>,
        W2: &PLONKWitness<E>,
    ) -> Result<(Vec<E::ScalarField>, Commitment<E>), NovaError> {
        //
    }
}

impl<E, F> PLONKWitness<E, F>
where
    E: Pairing,
    F: FftField,
{
    /// A method to create a witness object using a vector of scalars
    pub fn new(S: &PLONKShape<E>, W: &[[E::ScalarField]]) -> Result<PLONKWitness<E>, NovaError> {
        if S.num_wire_types != W.len() {
            Err(NovaError::InvalidWireTypes)
        } else {
            Ok(PLONKWitness { W: W.to_owned() })
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(
        &self,
        ck: E::ScalarField,
        domain: Radix2EvaluationDomain<F>,
    ) -> Vec<Commitment<E>> {
        let wire_polys = self
            .W
            .iter_par
            .map(|wire_var| DensePolynomial::from_coefficients_vec(domain.ifft(wire_var)));

        // commit
        let wire_commitment = wire_polys
            .iter_par
            .map(|poly| UnivariateKzgPCS::commit(&ck, poly));

        wire_commitment
    }
}

impl<E, F> PLONKInstance<E, F>
where
    E: Pairing,
    F: FftField,
{
    /// A method to create an instance object using consitituent elements
    pub fn new(
        S: &PLONKShape<E>,
        comm_W: &[Commitment<E>],
        X: &[E::ScalarField],
    ) -> Result<PLONKInstance<E>, NovaError> {
        if S.num_public_input != X.len() {
            Err(NovaError::InvalidPublicInput)
        } else {
            Ok(PLONKInstance {
                comm_W: *comm_W,
                X: X.to_owned(),
            })
        }
    }
}

////////////////////////////////////////////
// impl<E: Pairing> AbsorbInROTrait<E> for PLONKInstance<E> {
//     // fn absorb_in_ro(&self, ro: &mut E::RO) {
//     //     self.comm_W.absorb_in_ro(ro);
//     //     for x in &self.X {
//     //         ro.absorb(scalar_as_base::<E>(*x));
//     //     }
//     // }
// }

impl<E, F> RelaxedPLONKWitness<E, F>
where
    E: Pairing,
    F: FftField,
{
    // type CommitmentKey = UnivariateUniversalParams<E>;
    /// Produces a default RelaxedPLONKWitness given an PLONKShape
    pub fn default(S: &PLONKShape<E>) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: vec![vec![E::ScalarField::ZERO; S.num_cons], S.num_wire_types],
            E: vec![E::ScalarField::ZERO; S.num_cons],
        }
    }

    /// Initializes a new RelaxedPLONKWitness from an PLONKWitness
    pub fn from_plonk_witness(
        S: &PLONKShape<E>,
        witness: &PLONKWitness<E>,
    ) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: witness.W.clone(),
            E: vec![E::ScalarField::ZERO; S.num_cons],
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &UnivariateUniversalParams<E>) -> (Vec<Commitment<E>>, Commitment<E>) {
        // convert evaluation vector to polynomial coefficient
        let domain = &self.eval_domain;
        let wire_polys = self
            .W
            .iter_par
            .map(|wire_var| DensePolynomial::from_coefficients_vec(domain.ifft(wire_var)));
        let error_poly = DensePolynomial::from_coefficients_vec(domain.ifft(self.E));

        // commit
        let wire_commitment = wire_polys
            .iter_par
            .map(|poly| UnivariateKzgPCS::commit(&ck, poly));
        let error_commitment = UnivariateKzgPCS::commit(&ck, error_poly);
        (wire_commitment, error_commitment)
    }

    /// Folds an incoming PLONKWitness into the current one
    pub fn fold(
        &self,
        W2: &PLONKWitness<E>,
        T: &[E::ScalarField],
        r: &E::ScalarField,
    ) -> Result<RelaxedPLONKWitness<E>, NovaError> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(NovaError::InvalidNumWireTypes);
        }

        let W = W1.par_iter().zip(W2).map(|(w1, w2)| {
            w1.zip(w2)
                .map(|(a, b)| *a + *r * *b)
                .collect::<Vec<E::ScalarField>>()
        });
        let E = E1.par_iter().zip(T).map(|(a, b)| *a + *r * *b).collect();
        Ok(RelaxedPLONKWitness { W, E })
    }

    // /// Pads the provided witness to the correct length
    // pub fn pad(&self, S: &PLONKShape<E>) -> RelaxedPLONKWitness<E> {
    //     let W = {
    //         let mut W = self.W.clone();
    //         W.extend(vec![G::ScalarField::ZERO; S.num_vars - W.len()]);
    //         W
    //     };

    //     let E = {
    //         let mut E = self.E.clone();
    //         E.extend(vec![G::ScalarField::ZERO; S.num_cons - E.len()]);
    //         E
    //     };

    //     Self { W, E }
    // }
}

impl<E, F> RelaxedPLONKInstance<E, F>
where
    E: Pairing,
    F: FftField,
{
    /// Produces a default RelaxedPLONKInstance given R1CSGens and PLONKShape
    pub fn default(
        _ck: &UnivariateUniversalParams<E>,
        S: &PLONKShape<E>,
    ) -> RelaxedPLONKInstance<E> {
        let (comm_W, comm_E) = (Commitment::<E>::default(), Commitment::<E>::default());
        RelaxedPLONKInstance {
            comm_W,
            comm_E,
            u: E::ScalarField::ZERO,
            X: vec![E::ScalarField::ZERO; S.num_public_input],
        }
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance(
        ck: &UnivariateUniversalParams<E>,
        S: &PLONKShape<E>,
        instance: &PLONKInstance<E>,
    ) -> RelaxedPLONKInstance<E> {
        let mut r_instance = RelaxedPLONKInstance::default(ck, S);
        r_instance.comm_W = instance.comm_W;
        r_instance.u = E::ScalarField::ONE;
        r_instance.X = instance.X.clone();
        r_instance
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance_unchecked(
        comm_W: &[Commitment<E>],
        X: &[E::ScalarField],
    ) -> RelaxedPLONKInstance<E> {
        RelaxedPLONKInstance {
            comm_W: *comm_W,
            comm_E: Commitment::<E>::default(),
            u: E::ScalarField::ONE,
            X: X.to_vec(),
        }
    }

    /// Folds an incoming RelaxedPLONKInstance into the current one
    pub fn fold(
        &self,
        U2: &PLONKInstance<E>,
        comm_T: &Commitment<E>,
        r: &E::ScalarField,
    ) -> Result<RelaxedPLONKInstance<E>, NovaError> {
        let (X1, u1, comm_W_1, comm_E_1) =
            (&self.X, &self.u, &self.comm_W.clone(), &self.comm_E.clone());
        let (X2, comm_W_2) = (&U2.X, &U2.comm_W);

        // weighted sum of X, comm_W, comm_E, and u
        let X = X1
            .par_iter()
            .zip(X2)
            .map(|(a, b)| *a + *r * *b)
            .collect::<Vec<E::ScalarField>>();
        let comm_W = *comm_W_1 + *comm_W_2 * *r;
        let comm_E = *comm_E_1 + *comm_T * *r;
        let u = *u1 + *r;

        Ok(RelaxedPLONKInstance {
            comm_W,
            comm_E,
            X,
            u,
        })
    }
}

// impl<E: Pairing> TranscriptReprTrait<E> for RelaxedPLONKInstance<E> {
//     fn to_transcript_bytes(&self) -> Vec<u8> {
//         [
//             self.comm_W.to_transcript_bytes(),
//             self.comm_E.to_transcript_bytes(),
//             self.u.to_transcript_bytes(),
//             self.X.as_slice().to_transcript_bytes(),
//         ]
//         .concat()
//     }
// }

impl<E: Pairing> AbsorbInROTrait<E> for RelaxedPLONKInstance<E> {
    // fn absorb_in_ro(&self, ro: &mut G::RO) {
    //     self.comm_W.absorb_in_ro(ro);
    //     self.comm_E.absorb_in_ro(ro);
    //     ro.absorb(scalar_as_base::<E>(self.u));

    //     // absorb each element of self.X in bignum format
    //     for x in &self.X {
    //         let limbs: Vec<G::ScalarField> =
    //             nat_to_limbs(&f_to_nat(x), BN_LIMB_WIDTH, BN_N_LIMBS).unwrap();
    //         for limb in limbs {
    //             ro.absorb(scalar_as_base::<E>(limb));
    //         }
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use jf_primitives::pcs::errors::PCSError;
    use jf_utils::test_rng;

    fn end_to_end_test_template<E: Pairing>() -> Result<(), PCSError> {
        let rng = &mut test_rng();
        for _ in 0..100 {
            let mut degree = 0;
            while degree <= 1 {
                degree = usize::rand(rng) % 20;
            }
            let pp = UnivariateKzgPCS::<E>::gen_srs_for_testing(rng, degree)?;
            let (ck, vk) = pp.trim(degree)?;
            let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<E::ScalarField>>::rand(
                degree, rng,
            );
            let comm = UnivariateKzgPCS::<E>::commit(&ck, &p)?;
            let point = E::ScalarField::rand(rng);
            let (proof, value) = UnivariateKzgPCS::<E>::open(&ck, &p, &point)?;
            assert!(
                UnivariateKzgPCS::<E>::verify(&vk, &comm, &point, &value, &proof)?,
                "proof was incorrect for max_degree = {}, polynomial_degree = {}",
                degree,
                p.degree(),
            );
        }
        Ok(())
    }

    #[test]
    fn end_to_end_test() {
        end_to_end_test_template::<Bls12_381>().expect("test failed for bls12-381");
    }
}
