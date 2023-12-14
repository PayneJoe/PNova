/// plonk instances for primary circuit over BN254 curve
///
/// computation of cross terms followed from chapter 3.5 of protostar: https://eprint.iacr.org/2023/620.pdf
///
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
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
    pub(crate) num_cons: usize,
    pub(crate) num_wire_types: usize,
    pub(crate) num_public_input: usize,

    pub(crate) q_lc: Vec<Vec<E::ScalarField>>,
    pub(crate) q_mul: Vec<Vec<E::ScalarField>>,
    pub(crate) q_hash: Vec<Vec<E::ScalarField>>,
    pub(crate) q_ecc: Vec<E::ScalarField>,
    pub(crate) q_o: Vec<E::ScalarField>,
    pub(crate) q_c: Vec<E::ScalarField>,
}

/// A type that holds a witness for a given Plonk instance
/// w_0, w_1, w_2, w_3, w_o
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKWitness<E: Pairing> {
    pub(crate) W: Vec<Vec<E::ScalarField>>,
}

/// A type that holds a commitment vector and public io vector
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKInstance<E: Pairing> {
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) X: Vec<E::ScalarField>,
}

/// relaxed witness
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKWitness<E: Pairing> {
    pub(crate) W: Vec<Vec<E::ScalarField>>,
    pub(crate) E: Vec<Vec<E::ScalarField>>,
}

/// relaxed instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKInstance<E: Pairing> {
    pub(crate) comm_W: Vec<Commitment<E>>,
    pub(crate) comm_E: Vec<Commitment<E>>,
    pub(crate) X: Vec<E::ScalarField>,
    pub(crate) u: E::ScalarField,
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
            E: (0..S.num_wire_types - 1)
                .map(|_| vec![<E::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<E::ScalarField>>>(),
        }
    }

    /// Initializes a new RelaxedPLONKWitness from an R1CSWitness
    pub fn from_plonk_witness(
        S: &PLONKShape<E>,
        witness: &PLONKWitness<E>,
    ) -> RelaxedPLONKWitness<E> {
        RelaxedPLONKWitness {
            W: witness.W.clone(),
            E: (0..S.num_wire_types - 1)
                .map(|_| vec![<E::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<E::ScalarField>>>(),
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<E>) -> (Vec<Commitment<E>>, Vec<Commitment<E>>) {
        let com_func = |vecs: &Vec<Vec<E::ScalarField>>| {
            vecs.iter()
                .map(|v| {
                    let p = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
                        E::ScalarField,
                    >>::from_coefficients_vec(v.to_vec());
                    UnivariateKzgPCS::<E>::commit(ck, &p).unwrap()
                })
                .collect::<Vec<Commitment<E>>>()
        };

        let comm_W = com_func(&self.W);
        let comm_E = com_func(&self.E);

        (comm_W, comm_E)
    }

    pub fn fold(
        &self,
        W2: &PLONKWitness<E>,
        T: &Vec<Vec<E::ScalarField>>,
        r: &E::ScalarField,
    ) -> Result<RelaxedPLONKWitness<E>, MyError> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(MyError::WitnessError);
        }

        let fold_scalar_func = |a_vecs: &Vec<Vec<E::ScalarField>>,
                                b_vecs: &Vec<Vec<E::ScalarField>>| {
            a_vecs
                .par_iter()
                .zip(b_vecs)
                .map(|(a_col, b_col)| {
                    a_col
                        .par_iter()
                        .zip(b_col)
                        .map(|(a, b)| *a + *r * *b)
                        .collect::<Vec<E::ScalarField>>()
                })
                .collect::<Vec<Vec<E::ScalarField>>>()
        };
        let W = fold_scalar_func(&W1, &W2);
        let E = fold_scalar_func(&E1, T);

        Ok(RelaxedPLONKWitness { W, E })
    }
}

impl<E: Pairing> RelaxedPLONKInstance<E> {
    pub fn default(_ck: &CommitmentKey<E>, S: &PLONKShape<E>) -> RelaxedPLONKInstance<E> {
        let (comm_W, comm_E) = (
            (0..S.num_wire_types)
                .map(|_| Commitment::<E>::default())
                .collect::<Vec<Commitment<E>>>(),
            (0..S.num_wire_types - 1)
                .map(|_| Commitment::<E>::default())
                .collect::<Vec<Commitment<E>>>(),
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
        let comm_E = (0..comm_W.len() - 1)
            .map(|_| Commitment::<E>::default())
            .collect::<Vec<Commitment<E>>>();
        RelaxedPLONKInstance {
            comm_W: comm_W.to_owned(),
            comm_E: comm_E,
            u: E::ScalarField::ONE,
            X: X.to_vec(),
        }
    }

    /// Folds an incoming RelaxedPLONKInstance into the current one
    pub fn fold(
        &self,
        U2: &PLONKInstance<E>,
        comm_T: &Vec<Commitment<E>>,
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

        let fold_comm_func = |comm_1: &Vec<Commitment<E>>, comm_2: &Vec<Commitment<E>>| {
            comm_1
                .par_iter()
                .zip(comm_2)
                .map(|(a, b)| {
                    let a_affine: &E::G1Affine = a.as_ref();
                    let b_affine: &E::G1Affine = b.as_ref();
                    Commitment((*a_affine + *b_affine * *r).into_affine())
                })
                .collect::<Vec<Commitment<E>>>()
        };

        let comm_W = fold_comm_func(&self.comm_W, &U2.comm_W);
        let comm_E = fold_comm_func(&self.comm_E, comm_T);

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
        q_hash: &Vec<Vec<E::ScalarField>>,
        q_o: &Vec<E::ScalarField>,
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
            vec![q_c, q_ecc, q_o],
            q_lc.into_iter().collect::<Vec<&Vec<E::ScalarField>>>(),
            q_mul.into_iter().collect::<Vec<&Vec<E::ScalarField>>>(),
            q_hash.into_iter().collect::<Vec<&Vec<E::ScalarField>>>(),
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
        })
    }

    fn grand_product(n: usize, vec: Vec<&E::ScalarField>) -> E::ScalarField {
        let first: E::ScalarField = *vec[0];
        if n == 1 {
            first
        } else {
            vec[1..].iter().fold(first, |acc, cur| acc * *cur)
        }
    }

    fn compute_cross_terms(
        degree: usize,
        u1: E::ScalarField,
        u2: E::ScalarField,
        inst1: &Vec<Vec<E::ScalarField>>,
        inst2: &Vec<Vec<E::ScalarField>>,
    ) -> Vec<Vec<E::ScalarField>> {
        assert!(inst1.len() == inst2.len(), "compute cross term");

        let transpose_matrix = |mat: Vec<Vec<E::ScalarField>>| {
            let num_row = mat[0].len();
            let mut mut_cols: Vec<_> = mat.into_iter().map(|col| col.into_iter()).collect();
            (0..num_row)
                .map(|_| {
                    mut_cols
                        .iter_mut()
                        .map(|n| n.next().unwrap())
                        .collect::<Vec<E::ScalarField>>()
                })
                .collect::<Vec<Vec<E::ScalarField>>>()
        };
        let trans_inst1 = transpose_matrix(inst1.clone());
        let trans_inst2 = transpose_matrix(inst2.clone());

        let max_degree = 5 as usize;
        (1..max_degree)
            .rev()
            .map(|r_degree| {
                let l_degree = max_degree - r_degree;

                trans_inst1
                    .par_iter()
                    .zip(&trans_inst2)
                    .map(|(row_a, row_b)| {
                        let l_vars = vec![
                            vec![&u1; degree],
                            row_a
                                .into_iter()
                                .map(|a| a)
                                .collect::<Vec<&E::ScalarField>>(),
                        ]
                        .concat();
                        let r_vars = vec![
                            vec![&u2; degree],
                            row_b
                                .into_iter()
                                .map(|a| a)
                                .collect::<Vec<&E::ScalarField>>(),
                        ]
                        .concat();
                        // let l_vars = vec![vec![u1; degree], row_a].concat();
                        // let r_vars = vec![vec![u2; degree], row_b].concat();
                        Self::grand_product(l_degree, l_vars)
                            * Self::grand_product(r_degree, r_vars)
                    })
                    .collect::<Vec<E::ScalarField>>()
            })
            .rev()
            .collect::<Vec<Vec<E::ScalarField>>>()
    }

    fn compute_cross_terms_five_exp(
        inst1: &Vec<E::ScalarField>,
        inst2: &Vec<E::ScalarField>,
    ) -> Vec<Vec<E::ScalarField>> {
        let count_combination = |n: usize, r: usize| {
            if r > n {
                0
            } else {
                (1..=r).fold(1, |acc, val| acc * (n - val + 1) / val)
            }
        };
        let vec_pow = |n: usize, vec: &Vec<E::ScalarField>| {
            vec.par_iter()
                .map(|v| {
                    let first = *v;
                    if n == 1 {
                        first
                    } else {
                        vec![v; n - 1].iter().fold(first, |a, b| a * *b)
                    }
                })
                .collect::<Vec<E::ScalarField>>()
        };

        let max_degree: usize = 5;
        (1..max_degree)
            .rev()
            .map(|r_degree| {
                let l_degree = max_degree - r_degree;
                let const_var = count_combination(max_degree, r_degree);
                let const_scalar = <E::ScalarField as PrimeField>::from_bigint(
                    <E::ScalarField as PrimeField>::BigInt::from(const_var as u32),
                )
                .unwrap();
                let ref_const_scalar = &const_scalar;
                let l_pow = vec_pow(l_degree, inst1);
                let r_pow = vec_pow(r_degree, inst2);
                l_pow
                    .iter()
                    .zip(r_pow)
                    .map(|(a, b)| *ref_const_scalar * a * b)
                    .collect::<Vec<E::ScalarField>>()
            })
            .rev()
            .collect::<Vec<Vec<E::ScalarField>>>()
    }

    //// compute cross terms and their commitments
    /// 1. length of cross term vector equals max_degree - 1
    pub fn commit_T(
        &self,
        ck: &CommitmentKey<E>,
        U1: &RelaxedPLONKInstance<E>,
        W1: &RelaxedPLONKWitness<E>,
        U2: &PLONKInstance<E>,
        W2: &PLONKWitness<E>,
    ) -> Result<(Vec<Vec<E::ScalarField>>, Vec<Commitment<E>>), MyError> {
        assert!(W1.W.len() == self.num_wire_types - 1, "wrong wires");
        // q_ecc operation, u^0 * q_ecc * w_0 * w_1 * w_2 * w_3 * w_o
        let ecc_T: Vec<Vec<E::ScalarField>> = Self::compute_cross_terms(
            0 as usize,
            U1.u,
            <E::ScalarField as Field>::ONE,
            &W1.W,
            &W2.W,
        );

        // q_lc operation, u^4 * (q_lc_0 * w_0 + q_lc_1 * w_1 + q_lc_2 * w_2 + q_lc_3 * w_3)
        let lc_T = (0..self.num_wire_types - 1)
            .map(|i| {
                Self::compute_cross_terms(
                    4,
                    U1.u,
                    <E::ScalarField as Field>::ONE,
                    &W1.W[i..i + 1].to_vec(),
                    &W2.W[i..i + 1].to_vec(),
                )
            })
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        // q_mul operation, u^3 * (q_mul_0 * w_0 * w_1 + q_mul_1 * w_2 * w_3)
        let mul_T = (0..self.num_wire_types - 1)
            .step_by(2)
            .map(|i| {
                Self::compute_cross_terms(
                    3,
                    U1.u,
                    <E::ScalarField as Field>::ONE,
                    &W1.W[i..i + 2].to_vec(),
                    &W2.W[i..i + 2].to_vec(),
                )
            })
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        // q_out operation, u^4 * (q_o * w_o)
        let out_T = Self::compute_cross_terms(
            4,
            U1.u,
            <E::ScalarField as Field>::ONE,
            &W1.W[self.num_wire_types - 1..].to_vec(),
            &W2.W[self.num_wire_types - 1..].to_vec(),
        );

        // q_c operation, u^5 * q_c
        let u1_vec = vec![U1.u; self.num_cons];
        let u2_vec = vec![<E::ScalarField as Field>::ONE; self.num_cons];
        let const_T = Self::compute_cross_terms_five_exp(&u1_vec, &u2_vec);

        // q_hash operation, u^0 * (q_hash_0 * w_0^5 + q_hash_1 * w_1^5 + q_hash_2 * w_2^5 + q_hash_3 * w_3^5)
        let hash_T = (0..self.num_wire_types - 1)
            .map(|i| Self::compute_cross_terms_five_exp(&W1.W[i], &W2.W[i]))
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        //////////////////////////////// apply selectors on cross terms
        let apply_selector = |T: &Vec<Vec<E::ScalarField>>, selector: &Vec<E::ScalarField>| {
            (0..self.num_wire_types - 1)
                .map(|i| {
                    let ref_T = &T[i];
                    ref_T
                        .par_iter()
                        .zip(selector)
                        .map(|(a, b)| *a * *b)
                        .collect::<Vec<E::ScalarField>>()
                })
                .collect::<Vec<Vec<E::ScalarField>>>()
        };

        let (ref_ecc_T, ref_out_T, ref_const_T, ref_q_ecc, ref_q_out, ref_q_const) =
            (&ecc_T, &out_T, &const_T, &self.q_ecc, &self.q_o, &self.q_c);
        let ecc_result = apply_selector(ref_ecc_T, ref_q_ecc);
        let out_result = apply_selector(ref_out_T, ref_q_out);
        let const_result = apply_selector(ref_const_T, ref_q_const);

        let lc_result = (0..self.num_wire_types - 1)
            .map(|i| {
                let (ref_lc_T, ref_q_lc) = (&lc_T[i], &self.q_lc[i]);
                apply_selector(ref_lc_T, ref_q_lc)
            })
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        let hash_result = (0..self.num_wire_types - 1)
            .map(|i| {
                let (ref_hash_T, ref_q_hash) = (&hash_T[i], &self.q_hash[i]);
                apply_selector(ref_hash_T, ref_q_hash)
            })
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        let mul_result = (0..2)
            .map(|i| {
                let (ref_mul_T, ref_q_mul) = (&mul_T[i], &self.q_mul[i]);
                apply_selector(ref_mul_T, ref_q_mul)
            })
            .collect::<Vec<Vec<Vec<E::ScalarField>>>>();

        ////////////////////////////////////////// add-on all cross terms
        let apply_mat_element_add =
            |acc: &Vec<Vec<E::ScalarField>>, cur: &Vec<Vec<E::ScalarField>>| {
                acc.into_iter()
                    .zip(cur)
                    .map(|(a_col, b_col)| {
                        a_col
                            .iter()
                            .zip(b_col)
                            .map(|(a, b)| *a + *b)
                            .collect::<Vec<E::ScalarField>>()
                    })
                    .collect::<Vec<Vec<E::ScalarField>>>()
            };

        let stack_T = vec![
            vec![&ecc_result, &out_result, &const_result],
            lc_result.iter().collect::<Vec<&Vec<Vec<E::ScalarField>>>>(),
            hash_result
                .iter()
                .collect::<Vec<&Vec<Vec<E::ScalarField>>>>(),
            mul_result
                .iter()
                .collect::<Vec<&Vec<Vec<E::ScalarField>>>>(),
        ]
        .concat();
        let T = stack_T[1..].iter().fold(stack_T[0].clone(), |acc, cur| {
            apply_mat_element_add(&acc, cur)
        });

        ////////////////////////////////////////// commit T
        let com_T = T
            .iter()
            .map(|coefficients| {
                let poly = <DensePolynomial<E::ScalarField> as DenseUVPolynomial<
                        E::ScalarField,
                    >>::from_coefficients_vec(coefficients.clone());
                UnivariateKzgPCS::<E>::commit(ck, &poly).unwrap()
            })
            .collect::<Vec<Commitment<E>>>();

        Ok((T, com_T))
    }
}
