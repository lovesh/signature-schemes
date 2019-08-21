use failure::Error;

#[derive(Debug, Fail)]
pub enum DelgError {
    #[fail(
    display = "Verkey valid for {} messages but given {} messages",
    expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },
}

pub type DelgResult<T> = Result<T, DelgError>;