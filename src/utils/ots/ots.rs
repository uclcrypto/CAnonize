#![allow(deprecated)]

use ark_ec::{PrimeGroup, pairing::Pairing, };
use ark_std::{UniformRand, };
use generic_array::{GenericArray, typenum::U32};
use ark_ff::{ PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::{utils::errors::*};
use crate::utils::utils::{OTSignatureScheme, OTSignature, OTSignatureType, OTSSigningKey, OTSSigningKeyType, OTSPublicKey, OTSPublicKeyType};



//One- TIme Signature Scheme
#[derive(Debug)]
pub struct POTSignatureScheme {}
impl<E: Pairing> OTSignatureScheme<E> for POTSignatureScheme {

    fn generate_keys(&self) -> (OTSPublicKeyType<E>, OTSSigningKeyType<E>) {
        let sk = POTSSigningKey::new();
        let pk = POTSPublicKey::new(&sk);
        (OTSPublicKeyType::P(pk), OTSSigningKeyType::P(sk))
    }
}

/// Signature
#[derive(Clone, Debug, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct POTSignature<E:Pairing>{
    s1:E::ScalarField,
    s2:E::ScalarField,
}
impl<E: Pairing> OTSignature for POTSignature<E> {
    
}
#[derive(Clone, Debug)]

/// signing key
pub struct POTSSigningKey<E: Pairing> {
    a:E::ScalarField,
    b:E::ScalarField,
    c:E::ScalarField,
}

impl<E: Pairing> POTSSigningKey<E> {
    fn new() -> Self {
        let mut rng = ark_std::test_rng(); 
        POTSSigningKey { 
            a: E::ScalarField::rand(&mut rng),
            b: E::ScalarField::rand(&mut rng),
            c: E::ScalarField::rand(&mut rng),
        }
    }
}

impl<E: Pairing> OTSSigningKey<E> for POTSSigningKey<E> {
    
    fn osign(&self, h : &GenericArray<u8, U32>) ->  OTSignatureType<E>
    {
        let m=E::ScalarField::from_le_bytes_mod_order(h.as_slice());
        let sk1=self.a + self.b*m;
        let sk2=self.c*m;
        OTSignatureType::P(POTSignature{s1:sk1, s2:sk2})        
    }       
}


/// public key
#[derive(Debug,Copy, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct POTSPublicKey<E: Pairing> {
    pub vk_1: E::G1,
    pub vk_2: E::G1,
    pub hk: E::G1,
}

impl<E: Pairing> POTSPublicKey<E> {
    /// Generate a public key
    fn new(sk: &POTSSigningKey<E>) -> Self
    {
        let hk = E::G1::rand(&mut ark_std::test_rng() );
        POTSPublicKey {
            vk_1: E::G1::generator()*sk.a,
            vk_2: E::G1::generator()*sk.b+ hk*sk.c,
            hk,
        }
    }
}
impl<E: Pairing> OTSPublicKey<E> for POTSPublicKey<E>
{
    /// Verify a signature with the public key
    fn overify(
        &self,
        signature:  &OTSignatureType<E>,
        h:&GenericArray<u8, U32>,
        
    ) -> Result<(), SignatureError> {
        let m=E::ScalarField::from_le_bytes_mod_order(h.as_slice());
        let s = match signature {
            OTSignatureType::P(sig) => sig,
            _ => return Err(SignatureError::InvalidSignature),
        };
        let lhs=self.vk_1 + self.vk_2*m;
        let rhs= E::G1::generator()*s.s1 + self.hk*s.s2;
        if lhs != rhs {
            return Err(SignatureError::InvalidSignature);
        }
        Ok(())
    }
}



#[cfg(test)]
 mod tests {
     use ark_bls12_381::Bls12_381;
    use sha2::{ Sha256, Digest};
    use super::*;


    #[test]
    fn test_signature(){
        //let rng = ark_std::test_rng();
        let sk =POTSSigningKey::new();
        let pk = POTSPublicKey::new(&sk);

        let h = b"Hello";
        let hash = Sha256::digest(h);

        let signature = <POTSSigningKey<Bls12_381> as OTSSigningKey<Bls12_381>>::osign( &sk, &hash);

        assert!(pk.overify(&signature,&hash).is_ok());
    }
}