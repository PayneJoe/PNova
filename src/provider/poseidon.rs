use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;

use crate::poseidon::poseidon_constants::PoseidonDefaultConfigField;
use crate::traits::{ROConstantsTrait, ROTrait};

/// wrap a EXTERNAL object PoseidonConfig<F: PrimeField>, and implement LOCAL trait 'ROConstantsTrait'
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
pub struct PoseidonRO<BaseField: PrimeField>(PoseidonSponge<BaseField>);

impl<BaseField, ScalarField> ROTrait<BaseField, ScalarField> for PoseidonRO<BaseField>
where
    BaseField: PrimeField + PoseidonDefaultConfigField + Absorb,
    ScalarField: PrimeField,
{
    type Constants = PoseidonConstants<BaseField>;

    fn new(constants: Self::Constants) -> Self {
        Self(PoseidonSponge::<BaseField>::new(&constants.0))
    }

    fn absorb(&mut self, e: BaseField) {
        self.0.absorb(&e);
    }

    fn squeeze(&mut self) -> ScalarField {
        self.0.squeeze_field_elements::<ScalarField>(1 as usize)[0]
    }
}
