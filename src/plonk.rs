/// PLONK Instance
///
///
///
///
use crate::errors::NovaError;
use ark_ec::pairing::Pairing;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, Polynomial, Radix2EvaluationDomain,
};
use jf_primitives::pcs::prelude::{Commitment, UnivariateKzgPCS};
use jf_utils::par_utils::parallelizable_slice_iter;

/// Public parameters for a given PLONK
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONK<E: Pairing> {
    _p: PhantomData<E>,
}

// A type that holds the shape of the PLONK circuit
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKShape<E: Pairing> {
    // number of constrain or gate, row number
    pub(crate) num_cons: usize,
    // number of wire types, column number
    pub(crate) num_wire_types: usize,
    // number of public input gate
    pub(crate) num_public_input: usize,

    // PLONK selectors
    pub(crate) q_c: Vec<E::ScalarFieldField>,
    // with length 5 or 6
    pub(crate) q_lc: Vec<Vec<E::ScalarFieldField>>,
    // with length 2
    pub(crate) q_mul: Vec<Vec<E::ScalarFieldField>>,
    pub(crate) q_ecc: Vec<E::ScalarFieldField>,
    pub(crate) q_hash: Vec<E::ScalarFieldField>,
    pub(crate) q_o: Vec<E::ScalarFieldField>,
    pub(crate) q_e: Vec<E::ScalarFieldField>,
}

/// A type that holds witness vectors for a given PLONK instance
/// The size of wire list is 5 for TurboPlonk, and 6 for UltraPlonk
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PLONKWitness<E: Pairing> {
    W: Vec<Vec<E::ScalarFieldField>>,
}

/// A type that holds an PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PLONKInstance<E: Pairing> {
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) X: Vec<E::ScalarFieldField>,
}

/// A type that holds a witness for a given Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaxedPLONKWitness<E: Pairing> {
    pub(crate) W: Vec<Vec<E::ScalarFieldField>>,
    pub(crate) E: Vec<E::ScalarFieldField>,
}

/// A type that holds a Relaxed PLONK instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RelaxedPLONKInstance<E: Pairing> {
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) comm_E: Commitment<E>,
    pub(crate) X: Vec<E::ScalarFieldField>,
    pub(crate) u: E::ScalarFieldField,
}

// impl<E: Pairing> PLONK<E> {
//     /// Samples public parameters for the specified number of constraints and variables in an PLONK
//     pub fn commitment_key(S: &PLONKShape<E>) -> CommitmentKey<E> {
//         let num_cons = S.num_cons;
//         let num_vars = S.num_vars;
//         let total_nz = S.A.len() + S.B.len() + S.C.len();
//         G::CE::setup(b"ck", max(max(num_cons, num_vars), total_nz))
//     }
// }

impl<E: Pairing> PLONKShape<E> {
    fn new(
        num_cons: usize,
        num_vars: usize,
        num_public_input: usize,
        q_c: Vec<E::ScalarFieldField>,
        q_lc: Vec<Vec<E::ScalarFieldField>>,
        q_mul: Vec<Vec<E::ScalarFieldField>>,
        q_ecc: Vec<E::ScalarFieldField>,
        q_hash: Vec<E::ScalarFieldField>,
        q_o: Vec<E::ScalarFieldField>,
        q_e: Vec<E::ScalarFieldField>,
    ) -> Result<PLONKShape<E>, NovaError> {
        // ....
        Ok(PLONKShape {
            num_cons,
            num_vars,
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
        ck: &CommitmentKey<E>,
        U: &RelaxedPLONKInstance<E>,
        W: &RelaxedPLONKWitness<E>,
    ) -> Result<(), NovaError> {
        //
    }

    /// Checks if the PLONK instance is satisfiable given a witness and its shape
    pub fn is_sat(
        &self,
        ck: &CommitmentKey<E>,
        U: &PLONKInstance<E>,
        W: &PLONKWitness<E>,
    ) -> Result<(), NovaError> {
        //
    }

    /// A method to compute a commitment to the cross-term `T` given a
    /// Relaxed PLONK instance-witness pair and an PLONK instance-witness pair
    pub fn commit_T(
        &self,
        ck: &CommitmentKey<E>,
        U1: &RelaxedPLONKInstance<E>,
        W1: &RelaxedPLONKWitness<E>,
        U2: &PLONKInstance<E>,
        W2: &PLONKWitness<E>,
    ) -> Result<(Vec<E::ScalarFieldField>, Commitment<E>), NovaError> {
        //
    }
}

impl<E: Pairing> PLONKWitness<E> {
    /// A method to create a witness object using a vector of scalars
    pub fn new(
        S: &PLONKShape<E>,
        W: &[[E::ScalarFieldField]],
    ) -> Result<PLONKWitness<E>, NovaError> {
        if S.num_wire_types != W.len() {
            Err(NovaError::InvalidWireTypes)
        } else {
            Ok(PLONKWitness { W: W.to_owned() })
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<E>) -> Commitment<E> {
        CE::<E>::commit(ck, &self.W)
    }
}

impl<E: Pairing> PLONKInstance<E> {
    /// A method to create an instance object using consitituent elements
    pub fn new(
        S: &PLONKShape<E>,
        comm_W: &[Commitment<E>],
        X: &[E::ScalarFieldField],
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
impl<E: Pairing> AbsorbInROTrait<E> for PLONKInstance<E> {
    // fn absorb_in_ro(&self, ro: &mut E::RO) {
    //     self.comm_W.absorb_in_ro(ro);
    //     for x in &self.X {
    //         ro.absorb(scalar_as_base::<E>(*x));
    //     }
    // }
}

impl<E: Pairing> RelaxedPLONKWitness<E> {
    /// Produces a default RelaxedPLONKWitness given an PLONKShape
    pub fn default(S: &PLONKShape<E>) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: vec![[E::ScalarField::ZERO; S.num_cons], S.num_wire_types],
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
    pub fn commit(&self, ck: &CommitmentKey<E>) -> (Commitment<E>, Commitment<E>) {
        (CE::<E>::commit(ck, &self.W), CE::<E>::commit(ck, &self.E))
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
        let E = E1.par_iter().zip(E2).map(|(e1, e2)| {
            e1.zip(e2)
                .map(|(a, b)| *a + *r * *b)
                .collect::<Vec<E::ScalarField>>()
        });
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

impl<E: Pairing> RelaxedPLONKInstance<E> {
    /// Produces a default RelaxedPLONKInstance given R1CSGens and PLONKShape
    pub fn default(_ck: &CommitmentKey<E>, S: &PLONKShape<E>) -> RelaxedPLONKInstance<E> {
        let (comm_W, comm_E) = (Commitment::<E>::default(), Commitment::<E>::default());
        RelaxedPLONKInstance {
            comm_W,
            comm_E,
            u: G::ScalarField::ZERO,
            X: vec![G::ScalarField::ZERO; S.num_public_input],
        }
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance(
        ck: &CommitmentKey<E>,
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
        X: &[G::ScalarField],
    ) -> RelaxedPLONKInstance<E> {
        RelaxedPLONKInstance {
            comm_W: *comm_W,
            comm_E: Commitment::<E>::default(),
            u: G::ScalarField::ONE,
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
            .collect::<Vec<G::ScalarField>>();
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

impl<G: Pairing> TranscriptReprTrait<E> for RelaxedPLONKInstance<E> {
    // fn to_transcript_bytes(&self) -> Vec<u8> {
    //     [
    //         self.comm_W.to_transcript_bytes(),
    //         self.comm_E.to_transcript_bytes(),
    //         self.u.to_transcript_bytes(),
    //         self.X.as_slice().to_transcript_bytes(),
    //     ]
    //     .concat()
    // }
}

impl<G: Pairing> AbsorbInROTrait<E> for RelaxedPLONKInstance<E> {
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
pub(crate) mod test {
    use jf_utils::test_rng;

    fn end_to_end_test_template<E>() -> Result<(), PCSError>
    where
        E: Pairing,
    {
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
}