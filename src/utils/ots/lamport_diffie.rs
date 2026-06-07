
#![allow(deprecated)]
use ark_ec::pairing::Pairing;
use generic_array::{GenericArray, sequence::GenericSequence, typenum::U32};
use rand::Rng;
use sha2::{Sha256, Digest};

use crate::{utils::errors::*};
use crate::utils::utils::{OTSignatureScheme, OTSignature, OTSignatureType, OTSSigningKey, OTSSigningKeyType, OTSPublicKey, OTSPublicKeyType};

//Signature Scheme
#[derive(Debug)]
pub struct LDOTSignatureScheme {}
impl<E: Pairing> OTSignatureScheme<E> for LDOTSignatureScheme {

    fn generate_keys(&self) -> (OTSPublicKeyType<E>, OTSSigningKeyType<E>) {
        let sk = LDOTSSigningKey::new();
        let pk = LDOTSPublicKey::new(&sk);
        (OTSPublicKeyType::LD(pk), OTSSigningKeyType::LD(sk))
    }
}

/// Lamport-Diffie one-time signature
#[derive(Clone, Debug, Copy)]
pub struct LDOTSignature{
    vec:[GenericArray<u8,U32>;256],
}
impl LDOTSignature{
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for i in 0..256 {
            
            v.extend_from_slice(&self.vec[i]);
            
        }
        v
    }
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let expected_length = 256 * 32;  // 256 elements, each 32 bytes
        if bytes.len() != expected_length {
            return None;  // Invalid length
        }

        let mut vec = [GenericArray::<u8, U32>::default(); 256];  // Initialize the array

        let mut idx = 0;  // Byte index

        // Iterate through the bytes and reconstruct the GenericArray<u8, U32> elements
        for i in 0..256 {
            let slice = &bytes[idx..idx + 32];  // Slice out 32 bytes for each element
            vec[i] = GenericArray::clone_from_slice(slice);  // Create the GenericArray
            idx += 32;  // Increment index by 32 bytes
        }

        Some(LDOTSignature { vec })
    }
}
impl OTSignature for LDOTSignature {
    
}
#[derive(Clone, Debug)]

/// LDOTS-Improved signing key
pub struct LDOTSSigningKey {
    vec: [[GenericArray<u8,U32>;2];256],
}
impl LDOTSSigningKey {
    fn new() -> Self {
        let mut v= [[GenericArray::<u8, U32>::default();2];256];
        let mut rng = rand::rng();
        for i in 0..256{
            let sk0=GenericArray::generate(|_| rng.random::<u8>());
            let sk1=GenericArray::generate(|_| rng.random::<u8>());
            v[i]=[sk0,sk1];
        }
        LDOTSSigningKey {
            vec: v,
        }
    }
}

impl<E: Pairing> OTSSigningKey<E> for LDOTSSigningKey {
    
    fn osign(&self, h : &GenericArray<u8, U32>) ->  OTSignatureType<E>
    {
        let mut v= [GenericArray::<u8, U32>::default();256];
        let mut  b=0;
        for i in 0..32{
            for j in (0..8).rev() {
                let bit: usize = ((h[i] >> j) & 1) as usize;
                v[b]=self.vec[b][bit];
                b+=1;
            }
        }
        OTSignatureType::LD(LDOTSignature{vec:v})
    }

       
}



#[derive(Debug,Copy, Clone)]
pub struct LDOTSPublicKey {
    pub vec:[[GenericArray<u8,U32>; 2];256],
}


impl LDOTSPublicKey {
    /// Generate a public key
    pub fn new(sk: &LDOTSSigningKey ) -> Self
    {
        let mut pk=[[GenericArray::<u8, U32>::default(), GenericArray::<u8, U32>::default()];256];
        for i in 0..256{
            let [x0,x1] = sk.vec[i];
            pk[i]=[Sha256::digest(x0), Sha256::digest(x1)];
        } 
        LDOTSPublicKey{ vec: pk,}
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Iterate over the 2D array and serialize each GenericArray<u8, U32> as bytes
        for i in 0..256 {
            for j in 0..2 {
                bytes.extend_from_slice(&self.vec[i][j]);
            }
        }
        
        bytes
    }
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        // The expected length is 256 * 2 * 32 bytes
        let expected_length = 256 * 2 * 32;
        if bytes.len() != expected_length {
            return None; // Incorrect length, return None
        }

        let mut vec = [[GenericArray::<u8, U32>::default(); 2]; 256]; // Empty array to fill

        let mut idx = 0; // Index into the byte slice

        // Iterate over the 256x2 32-byte elements
        for i in 0..256 {
            for j in 0..2 {
                let slice = &bytes[idx..idx + 32]; // Slice the next 32 bytes for each GenericArray
                vec[i][j] = GenericArray::clone_from_slice(slice); // Convert the slice to GenericArray
                idx += 32; // Move the index by 32 bytes
            }
        }

        Some(LDOTSPublicKey { vec })
    }
}
impl<E: Pairing> OTSPublicKey<E> for LDOTSPublicKey
{
    /// Verify a signature with the public key
    fn overify(
        &self,
        signature:  &OTSignatureType<E>,
        h:&GenericArray<u8, U32>,
        
    ) -> Result<(), SignatureError> {
        let mut b=0;
        for i in 0..32{
            for j in (0..8).rev() {
                let bit: usize = ((h[i] >> j) & 1) as usize;
                if Sha256::digest(signature.ld_value().vec[b]) != self.vec[b][bit]{
                    return Err(SignatureError::InvalidSignature);
                }
                b += 1;
            }
        }
        Ok(())
    }
}


#[cfg(test)]
 mod tests {
     use ark_bls12_381::Bls12_381;

    use super::*;


    #[test]
    fn test_signature(){
        //let rng = ark_std::test_rng();
        let sk =LDOTSSigningKey::new();
        let pk = LDOTSPublicKey::new(&sk);

        let h = b"Hello";
        let hash = Sha256::digest(h);

        let signature = <LDOTSSigningKey as OTSSigningKey<Bls12_381>>::osign( &sk, &hash);

        assert!(pk.overify(&signature,&hash).is_ok());
    }
}