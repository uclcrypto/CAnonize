use ark_ec::{ pairing::Pairing, PrimeGroup};
use ark_std::{UniformRand, test_rng, rand::Rng};
use ark_ff::{ Zero, PrimeField};
use groth_sahai::prover::CProof;
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};

use crate::{utils::errors::*};
use crate::utils::utils::{CProofCanonical, CRS, Proofs, PublicKeyType, SchnorrProof, SchnorrProof2, SignatureScheme, SignatureSchemeType, SigningKeyType, UserRAComm, UserRAComm2};
use crate::utils::gs::GSU;

use sha2::{Digest, Sha256};


use groth_sahai::{CRS as CRSLib, statement::MSMEG1, data_structures::Matrix};
use groth_sahai::verifier::Verifiable;
pub struct RA<E:Pairing, > {
    pk: PublicKeyType<E> ,
    sk: SigningKeyType<E>,
}
impl<E:Pairing, > RA<E>{
    pub fn new( signature_scheme: &SignatureSchemeType)->Self {
        let mut rng = test_rng(); 
        let (pk, sk) = match signature_scheme {
            SignatureSchemeType::SPSImp(scheme) => {
                scheme.generate_keys(&E::ScalarField::zero()) 
            },
            SignatureSchemeType::BB(scheme) => {
                scheme.generate_keys(&E::ScalarField::rand(&mut rng))
            },
        };
        RA {
           pk,
            sk,
        }
    }
    pub fn get_pk(&self) -> &PublicKeyType<E>{
        &self.pk
    }
    // Submission GS proof verification using GS from library
    pub fn verify_proof(&self, pk: &E::G1, proof: &CProof<E>, crs: &CRSLib<E>) -> bool {
        let a_consts: Vec<E::G1Affine> = vec![E::G1::generator().into()];
        let b_consts: Vec<E::ScalarField> = vec![E::ScalarField::zero()];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero()]];
        let target: E::G1Affine = E::G1Affine::from(*pk);
        let equ: MSMEG1<E> = MSMEG1::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };
        equ.verify(&proof, crs)
    }
    
    pub fn user_registration_2<R: Rng>(&self, rng: &mut R, comm: &UserRAComm, crs: &CRS<E>) -> Result<UserRAComm2, URProofError> {
        let id = E::G1::deserialize_compressed(&*comm.id).unwrap();
        let pk = E::G1::deserialize_compressed(&*comm.pk).unwrap();
        match &comm.proof_type {
            
            // Schnorr proof AS
            Proofs::SC => {
                let p = SchnorrProof::<E>::deserialize_compressed(&*comm.proof).unwrap();
                let mut hasher = Sha256::new();        
                SchnorrProof::<E>::hash_schnorr(&mut hasher, &E::G1::generator(), self.pk.sps_imp_value(), &id,&pk, &p.commitment);
                let h = hasher.finalize();
                let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
                if !p.verify(&pk, &common_h) {
                    return Err(URProofError::ProofVerificationFailed);
                }
            },
            // Schnorr proof AN
            Proofs::SC2 => {
                let p = SchnorrProof2::<E>::deserialize_compressed(&*comm.proof).unwrap();
                let mut hasher = Sha256::new();        
                SchnorrProof2::<E>::hash_schnorr2(&mut hasher, &E::G1::generator(), self.pk.bb_value(), &id,&pk, &p.commitment);
                let h = hasher.finalize();
                let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
                if !p.verify(&pk, &self.pk.bb_value().v, &common_h) {
                    return Err(URProofError::ProofVerificationFailed);
                }
            }
            // GS proof AS
            Proofs::GSRA=> {
                let crs= match crs {
                    CRS::GS2(c) => c,
                    _ => panic!("Invalid CRS type for GSRA11 verification"),
                };
                let p= GSU::<E>::deserialize_compressed(&*comm.proof).unwrap();
                if ! p.verify(crs, &pk){
                    return Err(URProofError::ProofVerificationFailed);
                }
            },
            // GS library proof AS
            Proofs::GSProof =>{
                let p = CProofCanonical::<E>::deserialize_compressed(&*comm.proof).unwrap();
                let crs= match crs {
                    CRS::GSLIB(c) => c,
                    _ => panic!("Invalid CRS type for GSRA11 verification"),
                };
                if ! self.verify_proof(&pk,&p.0,crs){
                    return Err(URProofError::ProofVerificationFailed);
                }
            }
            _ =>{
                return Err(URProofError::ProofVerificationFailed);
            }
        }
        
        let signature = SigningKeyType::signature(&self.sk, rng,&id, &pk); 
        let mut signature_w= Vec::<u8>::new();
        match &self.pk {
            PublicKeyType::SPSImp(_) => {
                signature.sps_imp_value().serialize_compressed(&mut signature_w).unwrap();
            },
            PublicKeyType::BB(_) => {
                signature.bb_value().serialize_compressed(&mut  signature_w).unwrap();
            }
        };
        Ok(UserRAComm2 {
            signature: signature_w
        })

    }
}