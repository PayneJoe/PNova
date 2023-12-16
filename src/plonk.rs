/// plonk instances for primary circuit over BN254 curve
///
/// computation of cross terms followed from chapter 3.4 of protostar: https://eprint.iacr.org/2023/620.pdf
///
// use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
// use jf_primitives::pcs::prelude::Commitment;
// use jf_primitives::pcs::{
//     prelude::{PCSError, UnivariateKzgPCS, UnivariateProverParam, UnivariateUniversalParams},
//     PolynomialCommitmentScheme, StructuredReferenceString,
// };
use rand::rngs::StdRng;
use rayon::prelude::*;

use crate::error::MyError;
// use crate::primary::kzg::gen_srs_for_testing;
use crate::{
    traits::{CommitmentEngineTrait, Group},
    Commitment, CommitmentKey,
};

use std::marker::PhantomData;

// pub(crate) type CommitmentKey<G> = UnivariateProverParam<G>;

/// Public parameters for a given PLONK
#[derive(Clone)]
pub struct PLONK<G: Group> {
    _p: PhantomData<G>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKShape<G: Group> {
    pub(crate) num_cons: usize,
    pub(crate) num_wire_types: usize,
    pub(crate) num_public_input: usize,

    pub(crate) q_lc: Vec<Vec<<G as Group>::ScalarField>>,
    pub(crate) q_mul: Vec<Vec<<G as Group>::ScalarField>>,
    pub(crate) q_hash: Vec<Vec<<G as Group>::ScalarField>>,
    pub(crate) q_ecc: Vec<<G as Group>::ScalarField>,
    pub(crate) q_o: Vec<<G as Group>::ScalarField>,
    pub(crate) q_c: Vec<<G as Group>::ScalarField>,
}

/// A type that holds a witness for a given Plonk instance
/// w_0, w_1, w_2, w_3, w_o
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKWitness<G: Group> {
    pub(crate) W: Vec<Vec<<G as Group>::ScalarField>>,
}

/// A type that holds a commitment vector and public io vector
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PLONKInstance<G: Group> {
    pub(crate) comm_W: Vec<Commitment<G>>,
    pub(crate) X: Vec<<G as Group>::ScalarField>,
}

/// relaxed witness
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKWitness<G: Group> {
    pub(crate) W: Vec<Vec<<G as Group>::ScalarField>>,
    pub(crate) E: Vec<Vec<<G as Group>::ScalarField>>,
}

/// relaxed instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaxedPLONKInstance<G: Group> {
    pub(crate) comm_W: Vec<Commitment<G>>,
    pub(crate) comm_E: Vec<Commitment<G>>,
    pub(crate) X: Vec<<G as Group>::ScalarField>,
    pub(crate) u: <G as Group>::ScalarField,
}

impl<G: Group> PLONK<G> {
    pub fn commitment_key(rng: &mut StdRng, degree: usize) -> CommitmentKey<G> {
        G::CE::setup(rng, degree)
    }
}

impl<G: Group> PLONKShape<G> {}

impl<G: Group> PLONKWitness<G> {
    /// A method to create a witness object using a vector of scalars
    pub fn new(
        S: &PLONKShape<G>,
        W: &[Vec<<G as Group>::ScalarField>],
    ) -> Result<PLONKWitness<G>, MyError> {
        if S.num_wire_types != W.len() {
            Err(MyError::WitnessError)
        } else {
            Ok(PLONKWitness { W: W.to_owned() })
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<G>) -> Vec<Commitment<G>> {
        let com_W = self
            .W
            .iter()
            .map(|w| {
                G::CE::commit(ck, w.as_slice()).unwarp();
            })
            .collect::<Vec<Commitment<G>>>();
        com_W
    }
}

impl<G: Group> PLONKInstance<G> {
    /// A method to create an instance object using consitituent elements
    pub fn new(
        S: &PLONKShape<G>,
        comm_W: &Vec<Commitment<G>>,
        X: &[<G as Group>::ScalarField],
    ) -> Result<PLONKInstance<G>, MyError> {
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

impl<G: Group> RelaxedPLONKWitness<G> {
    /// Produces a default RelaxedPLONKWitness given an PLONKShape
    pub fn default(S: &PLONKShape<G>) -> RelaxedPLONKWitness<G> {
        RelaxedPLONKWitness {
            W: (0..S.num_wire_types)
                .map(|_| vec![<<G as Group>::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<<G as Group>::ScalarField>>>(),
            E: (0..S.num_wire_types - 1)
                .map(|_| vec![<<G as Group>::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<<G as Group>::ScalarField>>>(),
        }
    }

    /// Initializes a new RelaxedPLONKWitness from an R1CSWitness
    pub fn from_plonk_witness(
        S: &PLONKShape<G>,
        witness: &PLONKWitness<G>,
    ) -> RelaxedPLONKWitness<G> {
        RelaxedPLONKWitness {
            W: witness.W.clone(),
            E: (0..S.num_wire_types - 1)
                .map(|_| vec![<<G as Group>::ScalarField as Field>::ZERO; S.num_cons])
                .collect::<Vec<Vec<<G as Group>::ScalarField>>>(),
        }
    }

    /// Commits to the witness using the supplied generators
    pub fn commit(&self, ck: &CommitmentKey<G>) -> (Vec<Commitment<G>>, Vec<Commitment<G>>) {
        let com_func = |vecs: &Vec<Vec<<G as Group>::ScalarField>>| {
            vecs.iter()
                .map(|v| {
                    let p = <DensePolynomial<<G as Group>::ScalarField> as DenseUVPolynomial<
                        <G as Group>::ScalarField,
                    >>::from_coefficients_vec(v.to_vec());
                    UnivariateKzgPCS::<G>::commit(ck, &p).unwrap()
                })
                .collect::<Vec<Commitment<G>>>()
        };

        let comm_W = com_func(&self.W);
        let comm_E = com_func(&self.E);

        (comm_W, comm_E)
    }

    pub fn fold(
        &self,
        W2: &PLONKWitness<G>,
        T: &Vec<Vec<<G as Group>::ScalarField>>,
        r: &<G as Group>::ScalarField,
    ) -> Result<RelaxedPLONKWitness<G>, MyError> {
        let (W1, E1) = (&self.W, &self.E);
        let W2 = &W2.W;

        if W1.len() != W2.len() {
            return Err(MyError::WitnessError);
        }

        let fold_scalar_func =
            |a_vecs: &Vec<Vec<<G as Group>::ScalarField>>,
             b_vecs: &Vec<Vec<<G as Group>::ScalarField>>| {
                a_vecs
                    .par_iter()
                    .zip(b_vecs)
                    .map(|(a_col, b_col)| {
                        a_col
                            .par_iter()
                            .zip(b_col)
                            .map(|(a, b)| *a + *r * *b)
                            .collect::<Vec<<G as Group>::ScalarField>>()
                    })
                    .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
            };
        let W = fold_scalar_func(&W1, &W2);
        let E = fold_scalar_func(&E1, T);

        Ok(RelaxedPLONKWitness { W, E })
    }
}

impl<G: Group> RelaxedPLONKInstance<G> {
    pub fn default(_ck: &CommitmentKey<G>, S: &PLONKShape<G>) -> RelaxedPLONKInstance<G> {
        let (comm_W, comm_E) = (
            (0..S.num_wire_types)
                .map(|_| Commitment::<G>::default())
                .collect::<Vec<Commitment<G>>>(),
            (0..S.num_wire_types - 1)
                .map(|_| Commitment::<G>::default())
                .collect::<Vec<Commitment<G>>>(),
        );
        RelaxedPLONKInstance {
            comm_W,
            comm_E,
            u: <<G as Group>::ScalarField as Field>::ZERO,
            X: vec![<<G as Group>::ScalarField as Field>::ZERO; S.num_public_input],
        }
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance(
        ck: &CommitmentKey<G>,
        S: &PLONKShape<G>,
        instance: &PLONKInstance<G>,
    ) -> RelaxedPLONKInstance<G> {
        let mut r_instance = RelaxedPLONKInstance::default(ck, S);
        r_instance.comm_W = instance.comm_W.clone();
        r_instance.u = <<G as Group>::ScalarField as Field>::ONE;
        r_instance.X = instance.X.clone();
        r_instance
    }

    /// Initializes a new RelaxedPLONKInstance from an PLONKInstance
    pub fn from_plonk_instance_unchecked(
        comm_W: &Vec<Commitment<G>>,
        X: &[<G as Group>::ScalarField],
    ) -> RelaxedPLONKInstance<G> {
        let comm_E = (0..comm_W.len() - 1)
            .map(|_| Commitment::<G>::default())
            .collect::<Vec<Commitment<G>>>();
        RelaxedPLONKInstance {
            comm_W: comm_W.to_owned(),
            comm_E: comm_E,
            u: <G as Group>::ScalarField::ONE,
            X: X.to_vec(),
        }
    }

    /// Folds an incoming RelaxedPLONKInstance into the current one
    pub fn fold(
        &self,
        U2: &PLONKInstance<G>,
        comm_T: &Vec<Commitment<G>>,
        r: &<G as Group>::ScalarField,
    ) -> Result<RelaxedPLONKInstance<G>, MyError> {
        let (X1, u1, comm_W_1, comm_E_1) =
            (&self.X, &self.u, &self.comm_W.clone(), &self.comm_E.clone());
        let (X2, comm_W_2) = (&U2.X, &U2.comm_W);

        // weighted sum of X, comm_W, comm_E, and u
        let X = X1
            .par_iter()
            .zip(X2)
            .map(|(a, b)| *a + *r * *b)
            .collect::<Vec<<G as Group>::ScalarField>>();

        let fold_comm_func = |comm_1: &Vec<Commitment<G>>, comm_2: &Vec<Commitment<G>>| {
            comm_1
                .par_iter()
                .zip(comm_2)
                .map(|(a, b)| {
                    let a_affine: &E::G1Affine = a.as_ref();
                    let b_affine: &E::G1Affine = b.as_ref();
                    Commitment((*a_affine + *b_affine * *r).into_affine())
                })
                .collect::<Vec<Commitment<G>>>()
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

impl<G: Group> PLONKShape<G> {
    pub fn new(
        num_cons: usize,
        num_wire_types: usize,
        num_public_input: usize,
        q_c: &Vec<<G as Group>::ScalarField>,
        q_lc: &Vec<Vec<<G as Group>::ScalarField>>,
        q_mul: &Vec<Vec<<G as Group>::ScalarField>>,
        q_ecc: &Vec<<G as Group>::ScalarField>,
        q_hash: &Vec<Vec<<G as Group>::ScalarField>>,
        q_o: &Vec<<G as Group>::ScalarField>,
    ) -> Result<PLONKShape<G>, MyError> {
        assert!(q_lc.len() == num_wire_types - 1);
        assert!(q_mul.len() == 2);
        let is_valid =
            |num_cons: usize, q: &Vec<<G as Group>::ScalarField>| -> Result<(), MyError> {
                if (q.len() == num_cons) {
                    Ok(())
                } else {
                    Err(MyError::SelectorError)
                }
            };

        let invalid_num: i32 = vec![
            vec![q_c, q_ecc, q_o],
            q_lc.into_iter()
                .collect::<Vec<&Vec<<G as Group>::ScalarField>>>(),
            q_mul
                .into_iter()
                .collect::<Vec<&Vec<<G as Group>::ScalarField>>>(),
            q_hash
                .into_iter()
                .collect::<Vec<&Vec<<G as Group>::ScalarField>>>(),
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

    fn grand_product(n: usize, vec: Vec<&<G as Group>::ScalarField>) -> <G as Group>::ScalarField {
        let first: <G as Group>::ScalarField = *vec[0];
        if n == 1 {
            first
        } else {
            vec[1..].iter().fold(first, |acc, cur| acc * *cur)
        }
    }

    fn compute_cross_terms(
        degree: usize,
        u1: <G as Group>::ScalarField,
        u2: <G as Group>::ScalarField,
        inst1: &Vec<Vec<<G as Group>::ScalarField>>,
        inst2: &Vec<Vec<<G as Group>::ScalarField>>,
    ) -> Vec<Vec<<G as Group>::ScalarField>> {
        assert!(inst1.len() == inst2.len(), "compute cross term");

        let transpose_matrix = |mat: Vec<Vec<<G as Group>::ScalarField>>| {
            let num_row = mat[0].len();
            let mut mut_cols: Vec<_> = mat.into_iter().map(|col| col.into_iter()).collect();
            (0..num_row)
                .map(|_| {
                    mut_cols
                        .iter_mut()
                        .map(|n| n.next().unwrap())
                        .collect::<Vec<<G as Group>::ScalarField>>()
                })
                .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
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
                                .collect::<Vec<&<G as Group>::ScalarField>>(),
                        ]
                        .concat();
                        let r_vars = vec![
                            vec![&u2; degree],
                            row_b
                                .into_iter()
                                .map(|a| a)
                                .collect::<Vec<&<G as Group>::ScalarField>>(),
                        ]
                        .concat();
                        // let l_vars = vec![vec![u1; degree], row_a].concat();
                        // let r_vars = vec![vec![u2; degree], row_b].concat();
                        Self::grand_product(l_degree, l_vars)
                            * Self::grand_product(r_degree, r_vars)
                    })
                    .collect::<Vec<<G as Group>::ScalarField>>()
            })
            .rev()
            .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
    }

    fn compute_cross_terms_five_exp(
        inst1: &Vec<<G as Group>::ScalarField>,
        inst2: &Vec<<G as Group>::ScalarField>,
    ) -> Vec<Vec<<G as Group>::ScalarField>> {
        let count_combination = |n: usize, r: usize| {
            if r > n {
                0
            } else {
                (1..=r).fold(1, |acc, val| acc * (n - val + 1) / val)
            }
        };
        let vec_pow = |n: usize, vec: &Vec<<G as Group>::ScalarField>| {
            vec.par_iter()
                .map(|v| {
                    let first = *v;
                    if n == 1 {
                        first
                    } else {
                        vec![v; n - 1].iter().fold(first, |a, b| a * *b)
                    }
                })
                .collect::<Vec<<G as Group>::ScalarField>>()
        };

        let max_degree: usize = 5;
        (1..max_degree)
            .rev()
            .map(|r_degree| {
                let l_degree = max_degree - r_degree;
                let const_var = count_combination(max_degree, r_degree);
                let const_scalar = <<G as Group>::ScalarField as PrimeField>::from_bigint(
                    <<G as Group>::ScalarField as PrimeField>::BigInt::from(const_var as u32),
                )
                .unwrap();
                let ref_const_scalar = &const_scalar;
                let l_pow = vec_pow(l_degree, inst1);
                let r_pow = vec_pow(r_degree, inst2);
                l_pow
                    .iter()
                    .zip(r_pow)
                    .map(|(a, b)| *ref_const_scalar * a * b)
                    .collect::<Vec<<G as Group>::ScalarField>>()
            })
            .rev()
            .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
    }

    //// compute cross terms and their commitments
    /// 1. length of cross term vector equals max_degree - 1
    pub fn commit_T(
        &self,
        ck: &CommitmentKey<G>,
        U1: &RelaxedPLONKInstance<G>,
        W1: &RelaxedPLONKWitness<G>,
        U2: &PLONKInstance<G>,
        W2: &PLONKWitness<G>,
    ) -> Result<(Vec<Vec<<G as Group>::ScalarField>>, Vec<Commitment<G>>), MyError> {
        assert!(W1.W.len() == self.num_wire_types - 1, "wrong wires");
        // q_ecc operation, u^0 * q_ecc * w_0 * w_1 * w_2 * w_3 * w_o
        let ecc_T: Vec<Vec<<G as Group>::ScalarField>> = Self::compute_cross_terms(
            0 as usize,
            U1.u,
            <<G as Group>::ScalarField as Field>::ONE,
            &W1.W,
            &W2.W,
        );

        // q_lc operation, u^4 * (q_lc_0 * w_0 + q_lc_1 * w_1 + q_lc_2 * w_2 + q_lc_3 * w_3)
        let lc_T = (0..self.num_wire_types - 1)
            .map(|i| {
                Self::compute_cross_terms(
                    4,
                    U1.u,
                    <<G as Group>::ScalarField as Field>::ONE,
                    &W1.W[i..i + 1].to_vec(),
                    &W2.W[i..i + 1].to_vec(),
                )
            })
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        // q_mul operation, u^3 * (q_mul_0 * w_0 * w_1 + q_mul_1 * w_2 * w_3)
        let mul_T = (0..self.num_wire_types - 1)
            .step_by(2)
            .map(|i| {
                Self::compute_cross_terms(
                    3,
                    U1.u,
                    <<G as Group>::ScalarField as Field>::ONE,
                    &W1.W[i..i + 2].to_vec(),
                    &W2.W[i..i + 2].to_vec(),
                )
            })
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        // q_out operation, u^4 * (q_o * w_o)
        let out_T = Self::compute_cross_terms(
            4,
            U1.u,
            <<G as Group>::ScalarField as Field>::ONE,
            &W1.W[self.num_wire_types - 1..].to_vec(),
            &W2.W[self.num_wire_types - 1..].to_vec(),
        );

        // q_c operation, u^5 * q_c
        let u1_vec = vec![U1.u; self.num_cons];
        let u2_vec = vec![<<G as Group>::ScalarField as Field>::ONE; self.num_cons];
        let const_T = Self::compute_cross_terms_five_exp(&u1_vec, &u2_vec);

        // q_hash operation, u^0 * (q_hash_0 * w_0^5 + q_hash_1 * w_1^5 + q_hash_2 * w_2^5 + q_hash_3 * w_3^5)
        let hash_T = (0..self.num_wire_types - 1)
            .map(|i| Self::compute_cross_terms_five_exp(&W1.W[i], &W2.W[i]))
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        //////////////////////////////// apply selectors on cross terms
        let apply_selector =
            |T: &Vec<Vec<<G as Group>::ScalarField>>, selector: &Vec<<G as Group>::ScalarField>| {
                (0..self.num_wire_types - 1)
                    .map(|i| {
                        let ref_T = &T[i];
                        ref_T
                            .par_iter()
                            .zip(selector)
                            .map(|(a, b)| *a * *b)
                            .collect::<Vec<<G as Group>::ScalarField>>()
                    })
                    .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
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
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        let hash_result = (0..self.num_wire_types - 1)
            .map(|i| {
                let (ref_hash_T, ref_q_hash) = (&hash_T[i], &self.q_hash[i]);
                apply_selector(ref_hash_T, ref_q_hash)
            })
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        let mul_result = (0..2)
            .map(|i| {
                let (ref_mul_T, ref_q_mul) = (&mul_T[i], &self.q_mul[i]);
                apply_selector(ref_mul_T, ref_q_mul)
            })
            .collect::<Vec<Vec<Vec<<G as Group>::ScalarField>>>>();

        ////////////////////////////////////////// add-on all cross terms
        let apply_mat_element_add =
            |acc: &Vec<Vec<<G as Group>::ScalarField>>,
             cur: &Vec<Vec<<G as Group>::ScalarField>>| {
                acc.into_iter()
                    .zip(cur)
                    .map(|(a_col, b_col)| {
                        a_col
                            .iter()
                            .zip(b_col)
                            .map(|(a, b)| *a + *b)
                            .collect::<Vec<<G as Group>::ScalarField>>()
                    })
                    .collect::<Vec<Vec<<G as Group>::ScalarField>>>()
            };

        let stack_T = vec![
            vec![&ecc_result, &out_result, &const_result],
            lc_result
                .iter()
                .collect::<Vec<&Vec<Vec<<G as Group>::ScalarField>>>>(),
            hash_result
                .iter()
                .collect::<Vec<&Vec<Vec<<G as Group>::ScalarField>>>>(),
            mul_result
                .iter()
                .collect::<Vec<&Vec<Vec<<G as Group>::ScalarField>>>>(),
        ]
        .concat();
        let T = stack_T[1..].iter().fold(stack_T[0].clone(), |acc, cur| {
            apply_mat_element_add(&acc, cur)
        });

        ////////////////////////////////////////// commit T
        let com_T = T
            .iter()
            .map(|coefficients| {
                let poly = <DensePolynomial<<G as Group>::ScalarField> as DenseUVPolynomial<
                    <G as Group>::ScalarField,
                >>::from_coefficients_vec(coefficients.clone());
                UnivariateKzgPCS::<G>::commit(ck, &poly).unwrap()
            })
            .collect::<Vec<Commitment<G>>>();

        Ok((T, com_T))
    }
}
