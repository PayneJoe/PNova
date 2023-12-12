/// plonk instances for primary circuit over BN254 curve
///
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use jf_primitives::pcs::prelude::Commitment;
use jf_primitives::pcs::{
    prelude::{PCSError, UnivariateKzgPCS, UnivariateProverParam, UnivariateUniversalParams},
    PolynomialCommitmentScheme, StructuredReferenceString,
};
use rand::rngs::StdRng;
use rayon::prelude::*;

use crate::error::MyError;
use crate::primary::kzg::gen_srs_for_testing;

use std::marker::PhantomData;

type CommitmentKey<E> = UnivariateProverParam<E>;

/// Public parameters for a given PLONK
#[derive(Clone)]
pub struct PLONK<E: Pairing> {
    _p: PhantomData<E>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKShape<E: Pairing> {
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
}

/// A type that holds a witness for a given Plonk instance
/// w_0, w_1, w_2, w_3, w_o
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKWitness<E: Pairing> {
    W: Vec<Vec<E::ScalarField>>,
}

/// A type that holds a commitment vector and public io vector
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKInstance<E: Pairing> {
    comm_W: Vec<Commitment<E>>,
    X: Vec<E::ScalarField>,
}

/// relaxed witness
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKWitness<E: Pairing> {
    W: Vec<Vec<E::ScalarField>>,
    E: Vec<E::ScalarField>,
}

/// relaxed instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKInstance<E: Pairing> {
    comm_W: Vec<Commitment<E>>,
    comm_E: Commitment<E>,
    X: Vec<E::ScalarField>,
    u: E::ScalarField,
}

impl<E: Pairing> PLONK<E> {
    pub fn commitment_key(rng: &mut StdRng, degree: usize) -> CommitmentKey<E> {
        let pp: UnivariateUniversalParams<E> = gen_srs_for_testing(rng, degree, 1).unwrap();
        let (ck, _) = pp.trim(degree).unwrap();
        ck
    }
}

impl<E: Pairing> PLONKShape<E> {}

impl<E: Pairing> PLONKWitness<E> {
    /// A method to create a witness object using a vector of scalars
    pub fn new(S: &PLONKShape<E>, W: &[Vec<E::ScalarField>]) -> Result<PLONKWitness<E>, MyError> {
        if S.num_wire_types != W.len() {
            Err(MyError::WitnessError)
        } else {
            Ok(PLONKWitness { W: W.to_owned() })
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<E>) -> Vec<Commitment<E>> {
        let com_W = self
            .W
            .iter()
            .map(|w| {
                let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
                        E::ScalarField,
                    >>::from_coefficients_vec(w.to_vec());
                UnivariateKzgPCS::<E>::commit(ck, &p).unwrap()
            })
            .collect::<Vec<Commitment<E>>>();
        com_W
    }
}

impl<E: Pairing> PLONKInstance<E> {
    /// A method to create an instance object using consitituent elements
    pub fn new(
        S: &PLONKShape<E>,
        comm_W: &Vec<Commitment<E>>,
        X: &[E::ScalarField],
    ) -> Result<PLONKInstance<E>, MyError> {
        if S.num_public_input != X.len() {
            Err(MyError::PublicIntputError)
        } else {
            Ok(PLONKInstance {
                comm_W: comm_W.to_owned(),
                X: X.to_owned(),
            })
        }
    }
}

impl<E: Pairing> RelaxedPLONKWitness<E> {
    /// Produces a default RelaxedPLONKWitness given an PLONKShape
    pub fn default(S: &PLONKShape<E>) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: (0..S.num_wire_types)
                .map(|_| vec![<E::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<E::ScalarField>>>(),
            E: vec![<E::ScalarField as Field>::ZERO; S.num_cons],
        }
    }

    /// Initializes a new RelaxedPLONKWitness from an R1CSWitness
    pub fn from_plonk_witness(
        S: &PLONKShape<E>,
        witness: &PLONKWitness<E>,
    ) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: witness.W.clone(),
            E: vec![<E::ScalarField as Field>::ZERO; S.num_cons],
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<E>) -> (Vec<Commitment<E>>, Commitment<E>) {
        let com_W = self
            .W
            .iter()
            .map(|w| {
                let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
                    E::ScalarField,
                >>::from_coefficients_vec(w.to_vec());
                UnivariateKzgPCS::<E>::commit(ck, &p).unwrap()
            })
            .collect::<Vec<Commitment<E>>>();

        let poly_e = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
            E::ScalarField,
        >>::from_coefficients_vec(self.E.to_vec());

        let com_E = UnivariateKzgPCS::<E>::commit(ck, &poly_e).unwrap();
        (com_W, com_E)
    }

    pub fn fold(
        &self,
        W2: &PLONKWitness<E>,
        T: &[E::ScalarField],
        r: &E::ScalarField,
    ) -> Result<RelaxedPLONKWitness<E>, MyError> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(MyError::WitnessError);
        }

        let W = W1
            .par_iter()
            .zip(W2)
            .map(|(a_col, b_col)| {
                a_col
                    .par_iter()
                    .zip(b_col)
                    .map(|(a, b)| *a + *r * *b)
                    .collect::<Vec<E::ScalarField>>()
            })
            .collect::<Vec<Vec<E::ScalarField>>>();

        let E = E1
            .par_iter()
            .zip(T)
            .map(|(a, b)| *a + *r * *b)
            .collect::<Vec<E::ScalarField>>();
        Ok(RelaxedPLONKWitness { W, E })
    }
}

impl<E: Pairing> RelaxedPLONKInstance<E> {
    pub fn default(_ck: &CommitmentKey<E>, S: &PLONKShape<E>) -> RelaxedPLONKInstance<E> {
        let (comm_W, comm_E) = (
            (0..S.num_wire_types)
                .map(|_| Commitment::<E>::default())
                .collect::<Vec<Commitment<E>>>(),
            Commitment::<E>::default(),
        );
        RelaxedPLONKInstance {
            comm_W,
            comm_E,
            u: <E::ScalarField as Field>::ZERO,
            X: vec![<E::ScalarField as Field>::ZERO; S.num_public_input],
        }
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance(
        ck: &CommitmentKey<E>,
        S: &PLONKShape<E>,
        instance: &PLONKInstance<E>,
    ) -> RelaxedPLONKInstance<E> {
        let mut r_instance = RelaxedPLONKInstance::default(ck, S);
        r_instance.comm_W = instance.comm_W.clone();
        r_instance.u = <E::ScalarField as Field>::ONE;
        r_instance.X = instance.X.clone();
        r_instance
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance_unchecked(
        comm_W: &Vec<Commitment<E>>,
        X: &[E::ScalarField],
    ) -> RelaxedPLONKInstance<E> {
        RelaxedPLONKInstance {
            comm_W: comm_W.to_owned(),
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
    ) -> Result<RelaxedPLONKInstance<E>, MyError> {
        let (X1, u1, comm_W_1, comm_E_1) =
            (&self.X, &self.u, &self.comm_W.clone(), &self.comm_E.clone());
        let (X2, comm_W_2) = (&U2.X, &U2.comm_W);

        // weighted sum of X, comm_W, comm_E, and u
        let X = X1
            .par_iter()
            .zip(X2)
            .map(|(a, b)| *a + *r * *b)
            .collect::<Vec<E::ScalarField>>();
        let comm_W = comm_W_1
            .par_iter()
            .zip(comm_W_2)
            .map(|(com_w_1, com_w_2)| {
                let w_2_affine: &E::G1Affine = com_w_2.as_ref();
                let w_1_affine: &E::G1Affine = com_w_1.as_ref();
                Commitment((*w_1_affine + *w_2_affine * *r).into_affine())
            })
            .collect::<Vec<Commitment<E>>>();
        // let comm_W = *comm_W_1 + *comm_W_2 * *r;
        let E_1_affine: &E::G1Affine = comm_E_1.as_ref();
        let T_affine: &E::G1Affine = comm_T.as_ref();
        let comm_E = Commitment((*E_1_affine + *T_affine * *r).into_affine());
        let u = *u1 + *r;

        Ok(RelaxedPLONKInstance {
            comm_W,
            comm_E,
            X,
            u,
        })
    }
}

impl<E: Pairing> PLONKShape<E> {
    pub fn new(
        num_cons: usize,
        num_wire_types: usize,
        num_public_input: usize,
        q_c: &Vec<E::ScalarField>,
        q_lc: &Vec<Vec<E::ScalarField>>,
        q_mul: &Vec<Vec<E::ScalarField>>,
        q_ecc: &Vec<E::ScalarField>,
        q_hash: &Vec<E::ScalarField>,
        q_o: &Vec<E::ScalarField>,
        q_e: &Vec<E::ScalarField>,
    ) -> Result<PLONKShape<E>, MyError> {
        assert!(q_lc.len() == num_wire_types - 1);
        assert!(q_mul.len() == 2);
        let is_valid = |num_cons: usize, q: &Vec<E::ScalarField>| -> Result<(), MyError> {
            if (q.len() == num_cons) {
                Ok(())
            } else {
                Err(MyError::SelectorError)
            }
        };

        let invalid_num: i32 = vec![
            vec![q_c, q_ecc, q_hash, q_o, q_e],
            q_lc.into_iter().collect::<Vec<&Vec<E::ScalarField>>>(),
            q_mul.into_iter().collect::<Vec<&Vec<E::ScalarField>>>(),
        ]
        .concat()
        .iter()
        .map(|q| {
            if (is_valid(num_cons, q).is_err()) {
                1 as i32
            } else {
                0 as i32
            }
        })
        .collect::<Vec<i32>>()
        .iter()
        .sum();

        if (invalid_num > 0) {
            return Err(MyError::SelectorError);
        }

        Ok(PLONKShape {
            num_cons: num_cons,
            num_wire_types: num_wire_types,
            num_public_input: num_public_input,
            q_c: q_c.to_owned(),
            q_lc: q_lc.to_owned(),
            q_mul: q_mul.to_owned(),
            q_ecc: q_ecc.to_owned(),
            q_hash: q_hash.to_owned(),
            q_o: q_o.to_owned(),
            q_e: q_e.to_owned(),
        })
    }

    pub fn commit_T(
        &self,
        ck: &CommitmentKey<E>,
        U1: &RelaxedPLONKInstance<E>,
        W1: &RelaxedPLONKWitness<E>,
        U2: &PLONKInstance<E>,
        W2: &PLONKWitness<E>,
    ) -> Result<(Vec<E::ScalarField>, Commitment<E>), MyError> {
        todo!()
    }
}
