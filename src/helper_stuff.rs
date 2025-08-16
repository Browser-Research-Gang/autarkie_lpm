use autarkie::{fuzzer::stages::generate::generate, Visitor};
use libafl_bolts::HasLen;
use libafl::{inputs::Input, prelude::Generator, corpus::CorpusId};
use prost::Message;
use std::hash::Hash;
use crate::TargetType;

impl Hash for TargetType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.encode_to_vec().hash(state)
    }
}

impl Input for TargetType {
    /// Generate a name for this input
    fn generate_name(&self, idx: Option<CorpusId>) -> String {
        format!("id:{}", idx.unwrap_or(CorpusId(0)).0)
    }
}

impl HasLen for TargetType {
    fn len(&self) -> usize {
        self.encode_to_vec().len()
    }
}

pub struct AutarkieGenerator<'a> {
    visitor: &'a mut Visitor,
}

impl <'a, S> Generator<TargetType, S> for AutarkieGenerator<'a> {
    fn generate(&mut self, _state: &mut S) -> Result<TargetType, libafl::Error> {
        for _ in 0..1 {
            if let Some(input) = generate(self.visitor) {
                return Ok(input)
            }
        }
        panic!("FAILED");
        Err(libafl::Error::empty("Failed to generate input"))
    }
}

impl <'a> AutarkieGenerator<'a> {
    pub fn new(visitor: &'a mut Visitor) -> Self {
        Self {visitor}
    }
}



