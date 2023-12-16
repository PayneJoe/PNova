use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;

use std::marker::PhantomData;

use crate::poseidon::poseidon_constants::PoseidonDefaultConfigField;
use crate::traits::{ROConstantsTrait, ROTrait};

/// wrap a EXTERNAL object PoseidonConfig<F: PrimeField>, and implement LOCAL trait 'ROConstantsTrait'
#[derive(Clone)]
pub struct PoseidonConstants<BaseField: PrimeField>(PoseidonConfig<BaseField>);

impl<BaseField> ROConstantsTrait<BaseField> for PoseidonConstants<BaseField>
where
    BaseField: PoseidonDefaultConfigField,
{
    fn new(rate: usize) -> Self {
        Self(
            <BaseField as PoseidonDefaultConfigField>::get_default_poseidon_parameters(rate, false)
                .unwrap(),
        )
    }
}

/// wrap a EXTERNAL object PoseidonSponge, impl LOCAL trait ROTrait
pub struct PoseidonRO<BaseField: PrimeField, ScalarField: PrimeField> {
    ro: PoseidonSponge<BaseField>,
    _p: PhantomData<ScalarField>,
}

impl<BaseField, ScalarField> ROTrait<BaseField, ScalarField> for PoseidonRO<BaseField, ScalarField>
where
    BaseField: PrimeField + PoseidonDefaultConfigField + Absorb,
    ScalarField: PrimeField,
{
    type Constants = PoseidonConstants<BaseField>;

    fn new(constants: Self::Constants) -> Self {
        Self {
            ro: PoseidonSponge::<BaseField>::new(&constants.0),
            _p: PhantomData,
        }
    }

    fn absorb(&mut self, e: BaseField) {
        self.ro.absorb(&e);
    }

    fn squeeze(&mut self) -> ScalarField {
        self.ro.squeeze_field_elements::<ScalarField>(1 as usize)[0]
    }
}
