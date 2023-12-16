use crate::{
    error::MyError,
    plonk::*,
    traits::{Group, ROConstantsTrait, ROTrait},
    Commitment, CommitmentKey,
};
use std::marker::PhantomData;

pub struct NIFS<G: Group> {
    pub(crate) comm_T: Commitment<G>,
    _p: PhantomData<G>,
}

impl<G: Group> NIFS<G> {
    pub fn prove(
        ck: &CommitmentKey<G>,
        pp_digest: &<G as Group>::ScalarField,
        S: &PLONKShape<G>,
        U1: &RelaxedPLONKInstance<G>,
        W1: &RelaxedPLONKWitness<G>,
        U2: &PLONKInstance<G>,
        W2: &PLONKWitness<G>,
    ) -> Result<(NIFS<G>, (RelaxedPLONKInstance<G>, RelaxedPLONKWitness<G>)), MyError> {
        let constants = <<G as Group>::RO as ROTrait<
            <G as Group>::BaseField,
            <G as Group>::ScalarField,
        >>::Constants::new(3);
        let ro = <<G as Group>::RO as ROTrait<
            <G as Group>::BaseField,
            <G as Group>::ScalarField,
        >>::new(constants.clone());
        todo!()
    }
    pub fn verifiy(
        &self,
        pp_digest: &<G as Group>::ScalarField,
        U1: &RelaxedPLONKInstance<G>,
        U2: &PLONKInstance<G>,
    ) -> Result<RelaxedPLONKInstance<G>, MyError> {
        todo!()
    }
}
