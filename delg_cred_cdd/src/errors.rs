use failure::Error;

#[derive(Debug, Fail)]
pub enum DelgError {
    #[fail(
        display = "Setup parameters valid for {} messages but given {} messages",
        expected, given
    )]
    UnsupportedNoOfMessages { expected: usize, given: usize },

    #[fail(display = "Expected even level but odd given {}", given)]
    ExpectedEvenLevel { given: usize },

    #[fail(display = "Expected odd level but even given {}", given)]
    ExpectedOddLevel { given: usize },

    #[fail(
        display = "Number of attributes should be less than {} but given {}",
        expected, given
    )]
    MoreAttributesThanExpected { expected: usize, given: usize },

    #[fail(display = "Delegatee verkey not found in delegation link")]
    VerkeyNotFoundInDelegationLink {},

    #[fail(display = "No odd delegation links in the delegation chain")]
    NoOddLinksInChain {},

    #[fail(display = "No even delegation links in the delegation chain")]
    NoEvenLinksInChain {},
}

pub type DelgResult<T> = Result<T, DelgError>;
