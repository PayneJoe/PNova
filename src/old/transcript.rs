use crate::{error::MyError, group::Group};

//////////////////////////////////////////// transcript trait, for non-interactive snark protocol through Fiat-Shamir
pub trait TranscriptReprTrait<G: Group> {
    /// returns a byte representation of self to be added to the transcript
    fn to_transcript_bytes(&self) -> Vec<u8>;
}

// implement for array of any type T who implemented TranscriptReprTrait trait
impl<G: Group, T: TranscriptReprTrait<G>> TranscriptReprTrait<G> for &[T] {
    fn to_transcript_bytes(&self) -> Vec<u8> {
        self.iter()
            .flat_map(|t| t.to_transcript_bytes())
            .collect::<Vec<u8>>()
    }
}

pub trait TranscriptEngineTrait<G: Group> {
    /// initializes the transcript
    fn new(label: &'static [u8]) -> Self;

    /// returns a scalar element of the group as a challenge
    fn squeeze(&mut self, label: &'static [u8]) -> Result<G::Scalar, MyError>;

    /// absorbs any type that implements TranscriptReprTrait under a label
    fn absorb<T: TranscriptReprTrait<G>>(&mut self, label: &'static [u8], o: &T);

    /// adds a domain separator
    fn dom_sep(&mut self, bytes: &'static [u8]);
}
