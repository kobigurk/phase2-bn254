use std::fmt;

/// Determines if point compression should be used.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum UseCompression {
    Yes,
    No,
}

impl fmt::Display for UseCompression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UseCompression::Yes => write!(f, "Yes"),
            UseCompression::No => write!(f, "No"),
        }
    }
}

/// Determines if points should be checked to be infinity.
#[derive(Copy, Clone, PartialEq)]
pub enum CheckForCorrectness {
    Full,
    OnlyNonZero,
    OnlyInGroup,
    No,
}

impl fmt::Display for CheckForCorrectness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CheckForCorrectness::Full => write!(f, "Full"),
            CheckForCorrectness::OnlyNonZero => write!(f, "OnlyNonZero"),
            CheckForCorrectness::OnlyInGroup => write!(f, "OnlyInGroup"),
            CheckForCorrectness::No => write!(f, "No"),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ElementType::TauG1 => write!(f, "TauG1"),
            ElementType::TauG2 => write!(f, "TauG2"),
            ElementType::AlphaG1 => write!(f, "AlphaG1"),
            ElementType::BetaG1 => write!(f, "BetaG1"),
            ElementType::BetaG2 => write!(f, "BetaG2"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum BatchExpMode {
    Auto,
    Direct,
    BatchInversion,
}

impl fmt::Display for BatchExpMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BatchExpMode::Auto => write!(f, "Auto"),
            BatchExpMode::Direct => write!(f, "Direct"),
            BatchExpMode::BatchInversion => write!(f, "Batch inversion"),
        }
    }
}

/// Determines which batch exponentiation algorithm to use
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum SubgroupCheckMode {
    Auto,
    Direct,
    Batched,
}

impl fmt::Display for SubgroupCheckMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SubgroupCheckMode::Auto => write!(f, "Auto"),
            SubgroupCheckMode::Direct => write!(f, "Direct"),
            SubgroupCheckMode::Batched => write!(f, "Batched"),
        }
    }
}
