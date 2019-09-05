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

    #[fail(
        display = "Requested odd link at index {} but only {} odd links present",
        given_index, size
    )]
    NoOddLinkInChainAtGivenIndex { given_index: usize, size: usize },

    #[fail(
        display = "Requested even link at index {} but only {} even links present",
        given_index, size
    )]
    NoEvenLinkInChainAtGivenIndex { given_index: usize, size: usize },

    #[fail(
        display = "Same no of bases and exponents required. {} bases and {} exponents",
        bases, exponents
    )]
    UnequalNoOfBasesExponents { bases: usize, exponents: usize },

    #[fail(
    display = "Chain size is {} but expected size at least {}",
    actual_size, expected_size
    )]
    ChainIsShorterThanExpected {actual_size: usize, expected_size: usize},

    #[fail(display = "Error with message {:?}", msg)]
    GeneralError { msg: String },
}

pub type DelgResult<T> = Result<T, DelgError>;
