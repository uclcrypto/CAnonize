//! Module describing the signing procedures and structs

use ark_ec::{ PrimeGroup, pairing::Pairing, pairing::PairingOutput};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::{ UniformRand, Zero};
use ark_std::rand::Rng;
use crate::{utils::errors::*};
use crate::utils::utils::{SignatureScheme, Signature, SignatureType, SigningKey, SigningKeyType, PublicKey, PublicKeyType};


//Partially blind Boneh-Boyen Signature Scheme
#[derive(Debug)]
pub struct BBSignatureScheme;
impl< E: Pairing,> SignatureScheme<E> for BBSignatureScheme {

    fn generate_keys(&self, _d: &E::ScalarField) -> (PublicKeyType<E>, SigningKeyType<E>) {
        let sk = BBSigningKey::<E>::new();
        let pk=sk.generate_pk();
        (PublicKeyType::BB(pk), SigningKeyType::BB(sk))
    }
}

/// Partially blind Boneh-Boyen signature
#[derive(Clone, Debug, Copy,CanonicalSerialize, CanonicalDeserialize)]
pub struct BBSignature<E: Pairing>{
    /// sigma 1 point
    pub s1: E::G1,
    /// sigma 2 point
    pub s2: E::G2,
    /// sigma 3 point
    pub s3: E::G1,
    
}
impl< E: Pairing, > Signature<E> for BBSignature<E,> {
    
}
impl<E:Pairing> BBSignature<E>{
    pub fn unblind(&self, d: &E::ScalarField) -> BBSignature<E> {
        let s1 = self.s1 -(self.s3*d);
        let s2 = self.s2;
        let s3= E::G1::zero();
        BBSignature {
            s1,
            s2,
            s3,
        }
    }
}

/// Partially blind Boneh-Boyen signing key
#[derive(Clone, Debug)]
pub struct BBSigningKey<E: Pairing,> {
    x:E::ScalarField,
    h:E::G1,
}
impl<E:Pairing> BBSigningKey<E> {
    fn new()-> Self{
        let mut rng = ark_std::test_rng();
        let x=E::ScalarField::rand(&mut rng);
            let sk=BBSigningKey{
                x,
                h:E::G1::generator()*E::ScalarField::rand(&mut rng),
            };
            sk
    }
    fn generate_pk(&self) -> BBPublicKey<E> {
        let mut rng = ark_std::test_rng();
        let pk=BBPublicKey{ //TODO check
            u:E::G1::generator()*E::ScalarField::rand(& mut rng),
            v:E::G1::generator()*E::ScalarField::rand(&mut rng),
            h:self.h,
            e:E::pairing(E::G1::generator(),E::G2::generator())*self.x,
        };
        pk
    }
    
    
}
impl< E: Pairing, S: Signature<E> > SigningKey< E, S> for BBSigningKey<E> {
 

    /// Sign two values m1 and m2 in G1
    fn sign<R: Rng>(&self, rng: &mut R, m1: &E::G1, m2: &E::G1) ->  SignatureType<E>
    {
        let r = E::ScalarField::rand(rng);
        let s1 =E::G1::generator()*self.x+(*m1+*m2+self.h)*r;
        let s2 = E::G2::generator()*r;
        let s3 = E::G1::generator()*r;
        SignatureType::BB(BBSignature{
            s1,
            s2,
            s3
        })

       
    }
    
}
/// PBBB public key

#[derive(Debug)]
pub struct BBPublicKey<E: Pairing> {
    pub u: E::G1,
    pub v: E::G1,
    pub h: E::G1,
    pub e: PairingOutput<E>,
}

impl<E: Pairing> BBPublicKey<E> {
    
}

impl<E: Pairing> PublicKey<E> for BBPublicKey<E>
{
    /// Verify a signature with the public key
    fn verify(
        &self,
        signature:  &SignatureType<E>,
        m1:&E::G1,
        m2:&E::G1,
        
    ) -> Result<(), SignatureError> {

        //check if unblinded
        if signature.bb_value().s3.is_zero() {
            return Err(SignatureError::SignatureUnblinded);
        }
        let signature = signature.bb_value();


        let check1_left = E::pairing(signature.s1, E::G2::generator());
        let check1_right = self.e+E::pairing(*m1 +*m2 + self.h , signature.s2);
        if check1_left != check1_right {
            return Err(SignatureError::InvalidSignature);
        }
        
        let check2_left =E::pairing(signature.s3,E::G2::generator());
        let check2_right = E::pairing(E::G1::generator(), signature.s2);
        if check2_left != check2_right {
            return Err(SignatureError::InvalidSignature);
        }

        Ok(())
    }
}

#[cfg(test)]
 mod tests {
     use super::*;
     use ark_bls12_381::{
         Bls12_381,  G1Projective as G1,
         Fr as ScalarField,
     };
     use ark_ff::{ Zero};


    use crate:: utils::utils::{PublicKey};

    #[test]
    fn test_signature(){
        let mut rng = ark_std::test_rng();
        let d = ScalarField::rand(&mut rng);
        let sk= BBSigningKey::<Bls12_381>::new();
        let pk = sk.generate_pk();
        // let sk = SigningKey::<Bls12_381>::new(2, &mut thread_rng());
        // let pk = PublicKey::from(&sk);

        // Representation of the equivalence class over which to generate the signature is selected
        let id = ScalarField::rand(&mut rng);
        let m1=pk.u*id;
        let s = ScalarField::rand(&mut rng);
        let m2=pk.v*s+G1::generator()*d;
        let signature = <BBSigningKey<Bls12_381> as SigningKey<Bls12_381, BBSignature<Bls12_381>>>::sign(&sk, &mut rng, &m1, &m2);

        assert!(pk.verify(&signature,&m1,&m2).is_ok());
    }
    #[test]
    fn test_unblinding(){
        let mut rng = ark_std::test_rng();
        let d = ScalarField::rand(&mut rng);
        let sk= BBSigningKey::<Bls12_381>::new();
        let pk = sk.generate_pk();
        let id = ScalarField::rand(&mut rng);
        let m1=pk.u*id;
        let s = ScalarField::rand(&mut rng);
        let m2=pk.v*s+G1::generator()*d;
        let signature = <BBSigningKey<Bls12_381> as SigningKey<Bls12_381, BBSignature<Bls12_381>>>::sign(&sk, &mut rng,&m1, &m2);
        let signature2= signature.bb_value();
        let d = ScalarField::rand(&mut rng);
        let unblinded_signature = signature2.unblind(&d);
        let expected_signature=BBSignature::<Bls12_381>{
            s1:signature2.s1-(signature2.s3*d),
            s2:signature2.s2,
            s3:G1::zero(),
        };
        assert_eq!(unblinded_signature.s1, expected_signature.s1);
        assert_eq!(unblinded_signature.s2, expected_signature.s2);
        assert_eq!(unblinded_signature.s3, expected_signature.s3);
    }
}