use std::fmt;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SignatureError {
    UnmatchedCapacity,
    InvalidSignature,
    InvalidSecretKeyVector, 
    IoErrorWrite,
    SignatureUnblinded,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SignatureError::UnmatchedCapacity => write!(f, "The capacities do not match"),
            SignatureError::InvalidSignature => write!(f, "Invalid signature"),
            SignatureError::InvalidSecretKeyVector => {
                write!(f, "Failed to generate a secret key from the given array")
            }
            SignatureError::IoErrorWrite => write!(f, "Error writing in the IO stream"),
            SignatureError::SignatureUnblinded => write!(f, "Signature is not unblinded"),
        }
    }
}



#[derive(Debug)]
pub enum URProofError{
    ProofVerificationFailed,
}

impl Display for URProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            URProofError::ProofVerificationFailed => write!(f, "Schnorr Proof verification failed"),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum UserRegistrationError{
    InvalidRASignature,
}
impl Display for UserRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            UserRegistrationError::InvalidRASignature => write!(f, "Invalid RA signature"),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SubmissionError{
    InvalidRAProof,
    InvalidSAProof,
    InvalidTokenProof,
    InvalidOTS
}
impl Display for SubmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SubmissionError::InvalidRAProof => write!(f, "Invalid RA proof"),
            SubmissionError::InvalidSAProof => write!(f, "Invalid SA proof"),
            SubmissionError::InvalidTokenProof => write!(f, "Invalid Token proof"),
            SubmissionError::InvalidOTS => write!(f, "Invalid One-Time Signature"),
        }
    }
}
#[derive(Debug)]
pub enum FischlinError{
    ZeroFailure,
}

impl Display for FischlinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FischlinError::ZeroFailure => write!(f, "Fischlin proof generation failed: hash with b zeros not found"),
        }
    }
}