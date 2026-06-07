pub static  LAMBDA: u32 = 32;
pub static B_2: u32 = 512; // using B=4 (4 first bits of hash must be 0 for the Fischlin transform) B2 = 2^(B+5)
                           // also need to change starts_B_zero_bits function in utils.rs

pub const DOMAIN: &[u8] = b"ANONYMOUS_SURVEY_BLS12381:SHA-256_SSWU_RO_POP_"; //for hash to curve
pub mod utils;
pub mod survey_authority;
pub mod registration_authority;
pub mod as_user;
pub mod an_user;