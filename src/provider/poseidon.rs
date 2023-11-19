//! Poseidon Constants and Poseidon-based RO used in Nova
use crate::traits::{ROConstantsTrait, ROTrait};
use core::marker::PhantomData;
use ff::{PrimeField, PrimeFieldBits};
use generic_array::typenum::U24;
use neptune::{
    poseidon::PoseidonConstants,
    sponge::{
        api::{IOPattern, SpongeAPI, SpongeOp},
        vanilla::{Mode::Simplex, Sponge, SpongeTrait},
    },
    Strength,
};
use serde::{Deserialize, Serialize};

/// All Poseidon Constants that are used in Nova
#[derive(Clone, Serialize, Deserialize)]
pub struct PoseidonConstantsCircuit<Scalar: PrimeField>(PoseidonConstants<Scalar, U24>);

impl<Scalar> ROConstantsTrait<Scalar> for PoseidonConstantsCircuit<Scalar>
where
    Scalar: PrimeField + PrimeFieldBits,
{
    /// Generate Poseidon constants
    #[allow(clippy::new_without_default)]
    fn new() -> Self {
        Self(Sponge::<Scalar, U24>::api_constants(Strength::Standard))
    }
}

/// A Poseidon-based RO to use outside circuits
#[derive(Serialize, Deserialize)]
pub struct PoseidonRO<Base, Scalar>
where
    Base: PrimeField + PrimeFieldBits,
    Scalar: PrimeField + PrimeFieldBits,
{
    // Internal State
    state: Vec<Base>,
    constants: PoseidonConstantsCircuit<Base>,
    num_absorbs: usize,
    squeezed: bool,
    _p: PhantomData<Scalar>,
}

impl<Base, Scalar> ROTrait<Base, Scalar> for PoseidonRO<Base, Scalar>
where
    Base: PrimeField + PrimeFieldBits + Serialize + for<'de> Deserialize<'de>,
    Scalar: PrimeField + PrimeFieldBits,
{
    type Constants = PoseidonConstantsCircuit<Base>;

    fn new(constants: PoseidonConstantsCircuit<Base>, num_absorbs: usize) -> Self {
        Self {
            state: Vec::new(),
            constants,
            num_absorbs,
            squeezed: false,
            _p: PhantomData,
        }
    }

    /// Absorb a new number into the state of the oracle
    fn absorb(&mut self, e: Base) {
        assert!(!self.squeezed, "Cannot absorb after squeezing");
        self.state.push(e);
    }

    /// Compute a challenge by hashing the current state
    fn squeeze(&mut self, num_bits: usize) -> Scalar {
        // check if we have squeezed already
        assert!(!self.squeezed, "Cannot squeeze again after squeezing");
        self.squeezed = true;

        let mut sponge = Sponge::new_with_constants(&self.constants.0, Simplex);
        let acc = &mut ();
        let parameter = IOPattern(vec![
            SpongeOp::Absorb(self.num_absorbs as u32),
            SpongeOp::Squeeze(1u32),
        ]);

        sponge.start(parameter, None, acc);
        assert_eq!(self.num_absorbs, self.state.len());
        SpongeAPI::absorb(&mut sponge, self.num_absorbs as u32, &self.state, acc);
        let hash = SpongeAPI::squeeze(&mut sponge, 1, acc);
        sponge.finish(acc).unwrap();

        // Only return `num_bits`
        let bits = hash[0].to_le_bits();
        let mut res = Scalar::ZERO;
        let mut coeff = Scalar::ONE;
        for bit in bits[0..num_bits].into_iter() {
            if *bit {
                res += coeff;
            }
            coeff += coeff;
        }
        res
    }
}

#[cfg(test)]
mod tests {}
