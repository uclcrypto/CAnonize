//! Module describing the signing procedures and structs

use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{UniformRand,};
use ark_std::rand::Rng;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::{utils::errors::*};
use crate::utils::utils::{SignatureScheme, Signature, SignatureType, SigningKey, SigningKeyType, PublicKey, PublicKeyType};


//Signature Scheme
#[derive(Debug)]
pub struct SPSImpSignatureScheme;
impl< E: Pairing,> SignatureScheme<E> for SPSImpSignatureScheme {

    fn generate_keys(&self, _d: &E::ScalarField) -> (PublicKeyType<E>, SigningKeyType<E>) {
        let (pk, trapdoor) =SPSImpPublicKey::new();
        let sk = SPSImpSigningKey::from(&trapdoor);
        (PublicKeyType::SPSImp(pk), SigningKeyType::SPSImp(sk))
    }
}

/// SPS-improved signature
#[derive(Clone, Debug, Copy,CanonicalSerialize, CanonicalDeserialize)]
pub struct SPSImpSignature<E: Pairing>{
    /// rho point
    pub rho: E::G1,
    /// rho_hat point
    pub rho_hat: E::G1,
    /// psi point
    pub psi: E::G1,
    /// gamma points
    pub gamma: E::G1,
    /// tau point
    pub tau: E::G2,
    /// pi 
    pub pi: E::G1,
}
impl< E: Pairing, > Signature<E> for SPSImpSignature<E,> {
    
}

/// SPS-Improved signing key
#[derive(Clone, Debug)]
pub struct SPSImpSigningKey<E: Pairing,> {
    b:E::ScalarField,
    k0:E::ScalarField,
    l1:E::ScalarField,
    l2:E::ScalarField,
    d:E::ScalarField,
    e:E::ScalarField,
    k1:E::ScalarField,
    k2:E::ScalarField,
    k3:E::ScalarField,
    k4:E::ScalarField,
    k5:E::ScalarField,
    k6:E::ScalarField,
    hk:E::G1,
    
}
/// Generate signing key from a public key
impl< E: Pairing, > From<&SPSImpTrapdoor<E>> for SPSImpSigningKey<E> {
    fn from(trapdoor: &SPSImpTrapdoor<E>) -> SPSImpSigningKey<E> {

        let h = E::G1::generator();

        let mut rng = ark_std::test_rng();
        let b = E::ScalarField::rand(&mut rng);
        let k0 = E::ScalarField::rand(&mut rng);
        let l1 = E::ScalarField::rand(&mut rng);
        let l2 = E::ScalarField::rand(&mut rng);
        let d = E::ScalarField::rand(&mut rng);
        let e = E::ScalarField::rand(&mut rng);
        let k1 = trapdoor.k1;
        let k2 = trapdoor.k2;
        let k3 = trapdoor.k3;
        let k4 = trapdoor.k4;
        let k5 = trapdoor.k5;
        let k6 = trapdoor.k6;
        let hk = h *trapdoor.k;
        SPSImpSigningKey {
            b,
            k0,
            l1, l2,
            d,
            e,
            k1, k2, k3, k4, k5, k6,
            hk,
        }
    }
}

impl< E: Pairing, S: Signature<E> > SigningKey< E, S> for SPSImpSigningKey<E> {

    /// Sign two values m1 and m2 in G1
    fn sign<R: Rng>(&self, rng: &mut R, m1: &E::G1, m2: &E::G1) ->  SignatureType<E>
    {
        let r = E::ScalarField::rand(rng);
        let tag = E::ScalarField::rand(rng);

        let h = E::G1::generator();
        let h2 = E::G2::generator();

        let rho=h*r;
        let rho_hat=h*(r*self.b);
        let psi=h*(r*tag);
        let tau= h2*tag;
        let gamma = *m1*self.l1+*m2*self.l2+h*(self.k0+self.d*r+tag*self.e*r);

        let pi= *m1*(self.k1+self.l1*self.k6)+*m2*(self.k2+self.l2*self.k6)+h*((self.k0+(self.d+tag*self.e)*r)*self.k6+r*self.k3+self.b*r*self.k4+tag*r*self.k5)+self.hk;

        SignatureType::SPSImp(SPSImpSignature {
            rho,
            rho_hat,
            psi,
            gamma,
            tau,
            pi,
        })

       
    }
}
/// SPS-Improved public key

#[derive(Debug)]
pub struct SPSImpPublicKey<E: Pairing> {
    pub hk1a: E::G2,
    pub hk2a: E::G2,
    pub hk3a: E::G2,
    pub hk4a: E::G2,
    pub hk5a: E::G2,
    pub hk6a: E::G2,
    pub hka: E::G2,
    pub ha: E::G2,
}

pub struct SPSImpTrapdoor<E: Pairing>{
    k1: E::ScalarField,
    k2: E::ScalarField,
    k3: E::ScalarField,
    k4: E::ScalarField,
    k5: E::ScalarField,
    k6: E::ScalarField,
    k: E::ScalarField,
}

impl<E: Pairing> SPSImpPublicKey<E> {
    /// Generate a public key
    pub fn new( ) -> (SPSImpPublicKey<E>,SPSImpTrapdoor<E>)
    {
                                                                                                                                                                                                                                                                                                                                            
        let mut rng = ark_std::test_rng();
        let k = E::ScalarField::rand(&mut rng);
        let a = E::ScalarField::rand(&mut rng);
        let k1 = E::ScalarField::rand(&mut rng);
        let k2 = E::ScalarField::rand(&mut rng);
        let k3 = E::ScalarField::rand(&mut rng);
        let k4 = E::ScalarField::rand(&mut rng);
        let k5 = E::ScalarField::rand(&mut rng);
        let k6 = E::ScalarField::rand(&mut rng);

        let h2 = E::G2::generator();

        let hk1a = h2 * (k1 * a);
        let hk2a = h2 * (k2 * a);
        let hk3a = h2 * (k3 * a);
        let hk4a = h2 * (k4 * a);
        let hk5a = h2 * (k5 * a);
        let hk6a = h2 * (k6 * a);
        let hka = h2 * (k * a);
        let ha = h2 * a;
        

        let key: SPSImpPublicKey<E> = SPSImpPublicKey::<E> {
            hk1a,hk2a,hk3a,hk4a,hk5a,hk6a,
            hka,
            ha,
        };
        let trapdoor=SPSImpTrapdoor{
            k1,k2,k3,k4,k5,k6,
            k,
        };
        (key,trapdoor)
    }
}
impl<E: Pairing> PublicKey<E> for SPSImpPublicKey<E>
{
    /// Verify a signature with the public key
    fn verify(
        &self,
        signature:  &SignatureType<E>,//& SPSImpSignature<E>,
        m1:&E::G1,
        m2:&E::G1,
        
    ) -> Result<(), SignatureError> {
        let signature = signature.sps_imp_value();
        let check1_left = E::pairing(m1,self.hk1a)+
                     E::pairing(m2,self.hk2a)+
                     E::pairing(signature.rho,self.hk3a)+
                     E::pairing(signature.rho_hat,self.hk4a)+
                     E::pairing(signature.psi,self.hk5a)+
                     E::pairing(signature.gamma,self.hk6a)+
                     E::pairing(E::G1::generator(),self.hka);
        let check1_right = E::pairing(signature.pi,self.ha);
        if check1_left != check1_right {
            return Err(SignatureError::InvalidSignature);
        }
        
        let check2_left =E::pairing(signature.rho,signature.tau);
        let check2_right = E::pairing(signature.psi, E::G2::generator());
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
         Bls12_381, G1Projective as G1,
         Fr as ScalarField,
     };

    use crate::utils::utils::PublicKey;

    #[test]
    fn test_signature(){
        let mut rng = ark_std::test_rng();
        let (pk,trapdoor) = SPSImpPublicKey::<Bls12_381>::new();
        let sk =SPSImpSigningKey::<Bls12_381>::from(&trapdoor);

        let m1=G1::generator()*ScalarField::rand(&mut rng);
        let m2=G1::generator()*ScalarField::rand(&mut rng);
        let signature = <SPSImpSigningKey<Bls12_381> as SigningKey<Bls12_381, SPSImpSignature<Bls12_381>>>::sign( &sk, &mut rng,&m1, &m2);

        assert!(pk.verify(&signature,&m1,&m2).is_ok());
    }
    
}