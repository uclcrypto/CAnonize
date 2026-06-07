#![allow(deprecated)]
use ark_ec::{PrimeGroup, pairing::Pairing, pairing::PairingOutput as GT,
hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,map_to_curve_hasher::MapToCurve}, };
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,Compress, SerializationError, Write};
use ark_std::{UniformRand, rand::Rng};
use ark_ff::{ PrimeField, Fp, MontBackend};
use ark_bls12_381::g1::{ Config as G1Config};
use ark_bls12_381::g2::{ Config as G2Config};

use ark_ff::field_hashers::DefaultFieldHasher;
use crate::{utils::curve_hasher::MapToCurveBasedHasher as MCCH};
use sha2::{ Sha256, Digest};
use ark_std::{borrow::Borrow};
use ark_bls12_381::fr::FrConfig;

use groth_sahai::prover::{ CProof, Commit1,Commit2, EquProof};
use groth_sahai::data_structures::{Com1, Matrix, vec_to_col_vec, B1,};
use groth_sahai::{ CRS as CRSLib, AbstractCrs};
use generic_array::{GenericArray, typenum::U32};

use crate::utils::errors::{FischlinError,UserRegistrationError, SignatureError};
use crate::{B_2,LAMBDA, utils::signature::sps_improved::*, utils::ots::lamport_diffie::*, utils::signature::pbbb::*,DOMAIN, utils::ots::ots::*};
use crate::as_user::UserAS;
use crate::an_user::UserAN;
use crate::utils::gs::*;

//////////*******************USER*******************//////////
///User trait
pub trait UserTrait<'a,E:Pairing>{
    fn user_registration_1<CR>(&self, crs: &CRS<E>, rng: &mut CR) -> UserRAComm where CR:Rng;
    fn user_registration_3(&mut self,signature: &'a SignatureType<E>)-> Result<(), UserRegistrationError>;
    fn set_signature_sa(&mut self,signature: &'a SignatureType<E>) ;
    fn submission<R:Rng>(&self, rng: &mut R, crs: &CRS<E>,crs2:&CRS<E>, crs_exp2: &CRS<E>, ots_scheme: &OTSignatureSchemeType) -> SubmissionType<E> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>, <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2>;
}
//Users
#[derive(Copy, Clone)]
pub struct User<'a, E:Pairing>{
    user : UserType<'a, E>,
}
impl<'a, E:Pairing> User<'a, E>{
    pub fn new<R:Rng>(rng: &mut R, scheme_type : &SignatureSchemeType, pk_ra : &'a PublicKeyType<E>, pk_sa : &'a PublicKeyType<E>, vid: &'a E::ScalarField)-> Self {
        match scheme_type {
            SignatureSchemeType::SPSImp(_)=> {
                let user = UserAS::new(rng, pk_ra, pk_sa, vid);
                User{
                    user: UserType::AS(user),
                }
            },
            SignatureSchemeType::BB(_)=> {
                let user = UserAN::new(rng,pk_ra, pk_sa, vid);
                User{
                    user: UserType::AN(user),
                }
            },
        }
    }
    pub fn get_gid(&self) -> &E::G1 {
        match &self.user {
            UserType::AS(user) => &user.get_gid(),
            UserType::AN(user) => &user.get_vvid(),
        }
    }

}
impl<'a, E:Pairing> UserTrait<'a,E> for User<'a,E>{
    fn user_registration_1<CR>(&self, crs: &CRS<E>, rng: &mut CR) -> UserRAComm where CR:Rng {
        match &self.user {
            UserType::AS(u)=> u.user_registration_1(crs, rng),
            UserType::AN(u)=> u.user_registration_1(crs, rng),
        }
        
    }
    fn user_registration_3(&mut self,signature: &'a SignatureType<E>) -> Result<(), UserRegistrationError> {
        match &mut self.user {
            UserType::AS(user) => user.user_registration_3(signature),
            UserType::AN(user) => user.user_registration_3(signature),
        }
    }
    fn set_signature_sa(&mut self,signature: &'a SignatureType<E>)  {
        match &mut self.user {
            UserType::AS(user) => user.set_signature_sa(signature),
            UserType::AN(user) => user.set_signature_sa(signature),
        }
    }
    fn submission<R:Rng>(&self, rng: &mut R, crs: &CRS<E>,crs2:&CRS<E>, crs_exp2: &CRS<E>, ots_scheme: &OTSignatureSchemeType) -> SubmissionType<E> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>,
    <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2>{
        match &self.user {
            UserType::AS(user) => {
                user.submission(rng, crs, crs2, crs_exp2, ots_scheme)
            },
            UserType::AN(user) => user.submission(rng, crs,crs2, crs_exp2, ots_scheme),
        }
    }
    
}

#[derive(Copy, Clone)]
pub enum UserType<'a, E:Pairing>{
    AS(UserAS<'a, E>),
    AN(UserAN<'a, E>),
}

//////////*******************SIGNATURE*******************//////////
///Signature trait representing the signature that is output by sign().
pub trait Signature<E:Pairing>{}

#[derive(Clone, Debug)]
pub struct SignatureTypeCompressed{
   pub signature: Vec<u8>,
}
#[derive(Clone, Debug, Copy)]
pub enum SignatureType<E: Pairing>{
    SPSImp(SPSImpSignature<E>),
    BB(BBSignature<E>),
}

impl<E:Pairing> SignatureType<E> {
    pub fn sps_imp_value(&self) -> &SPSImpSignature<E> {
        match self {
            SignatureType::SPSImp(signature) => signature,   
            _ => panic!("Not SPSImp signature"),
        }
    }
    pub fn bb_value(&self) -> &BBSignature<E> {
        match self {
            SignatureType::BB(signature) => signature,
            _ => panic!("Not BB signature"),
        }
    }
    pub fn deserialize(bytes: &Vec<u8>, scheme: &SignatureSchemeType) -> SignatureType<E> {
        match scheme {
            SignatureSchemeType::SPSImp(_) => {
                let signature = SPSImpSignature::deserialize_compressed(&**bytes);
                SignatureType::SPSImp(signature.unwrap())
            },
            SignatureSchemeType::BB(_) => {
                let signature = BBSignature::deserialize_compressed(&**bytes);
                SignatureType::BB(signature.unwrap())
            },
        }
    }
}
/// Public key trait
pub trait PublicKey<E: Pairing> {
    /// Verify a signature
    fn verify(
        &self,
        signature: & SignatureType<E>,
        m1:&E::G1,
        m2:&E::G1,
        
    ) -> Result<(), SignatureError>;
}

pub enum PublicKeyType<E: Pairing>{
    SPSImp(SPSImpPublicKey<E>),
    BB(BBPublicKey<E>),
}
impl<E:Pairing> PublicKeyType<E> {
    pub fn verify(&self,signature: &SignatureType<E>, m1: &E::G1,m2: &E::G1) -> Result<(), SignatureError> {
        match self {
            PublicKeyType::SPSImp(pk) => {
                pk.verify(signature, m1, m2).unwrap(); //TODO check error handling
            }
            PublicKeyType::BB(pk) => {
                pk.verify(signature, m1, m2).unwrap();
            }
        };
        Ok(())
    }
    pub fn sps_imp_value(&self) -> &SPSImpPublicKey<E> {
        match self {
            PublicKeyType::SPSImp(pk) => pk,
            _ => panic!("Not SPSImp public key"),
        }
    }
    pub fn bb_value(&self) -> &BBPublicKey<E> {
        match self {
            PublicKeyType::BB(pk) => pk,
            _ => panic!("Not BB public key"),
        }
    }
}


///Signature scheme trait ///
pub trait SignatureScheme< E: Pairing>{
    fn generate_keys(&self, d: &E::ScalarField) -> (PublicKeyType<E>, SigningKeyType<E>);
}
#[derive(Debug)]
pub enum SignatureSchemeType {
    SPSImp(SPSImpSignatureScheme),
    BB(BBSignatureScheme),
}

impl SignatureSchemeType {
    pub fn sps_imp_value(&self) -> &SPSImpSignatureScheme {
        match self {
            SignatureSchemeType::SPSImp(scheme) => scheme,
            _ => panic!("Not SPSImp signature scheme"),
        }
    }
    pub fn bb_value(&self) -> &BBSignatureScheme {
        match self {
            SignatureSchemeType::BB(scheme) => scheme,
            _ => panic!("Not BB signature scheme"),
        }
    }
}

///////////////////////////////
///Signing key trait
pub trait SigningKey<  E: Pairing, S : Signature<E> > {
    /// Sign a message
    fn sign<R: Rng>(&self, rng: &mut R, m1: &E::G1, m2: &E::G1) -> SignatureType<E>;
}

pub enum SigningKeyType<E: Pairing>{
    SPSImp(SPSImpSigningKey<E>),
    BB(BBSigningKey<E>),
}

impl<E: Pairing,> SigningKeyType<E> {
    pub fn signature<R: Rng>(&self, rng: &mut R, m1: &E::G1, m2: &E::G1) -> SignatureType<E> {
        match self {
            SigningKeyType::SPSImp(signing_key) => {
                <SPSImpSigningKey<E> as SigningKey<E, SPSImpSignature<E>>>::sign(signing_key,rng, m1, m2)
            }
            SigningKeyType::BB(signing_key) => {
                <BBSigningKey<E> as SigningKey<E, BBSignature<E>>>::sign(signing_key, rng, m1, m2)
            }
        }
    }
}

//////////*******************OTS SIGNATURE*******************//////////
///////////////////////////////
/// OTSignature scheme 
/// 

pub trait OTSignature{}
#[derive(Debug)]
pub enum OTSignatureType<E: Pairing>{
    LD(LDOTSignature),
    P(POTSignature<E>),
}
impl<E: Pairing> OTSignatureType<E>{
    pub fn ld_value(&self) -> &LDOTSignature{
        match self {
            OTSignatureType::LD(signature) => signature, 
            _ => panic!("Not LD OTSignature"),  
        }
    }
    pub fn p_value(&self) -> &POTSignature<E>{
        match self {
            OTSignatureType::P(signature) => signature, 
            _ => panic!("Not P OTSignature"),  
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            OTSignatureType::LD(signature) => {
                signature.serialize()
            },
            OTSignatureType::P(signature) => {
                let mut serialized_bytes: Vec<u8> = Vec::new();
                signature.serialize_compressed(&mut serialized_bytes).unwrap();
                serialized_bytes
            },
        }
    }
    pub fn deserialize(bytes: &Vec<u8>, ots: &OTS) -> OTSignatureType<E> {
        match ots {
            OTS::LD => {
                let signature = LDOTSignature::deserialize(bytes);
                OTSignatureType::LD(signature.unwrap())
            },
            OTS::P => {
                let signature = POTSignature::<E>::deserialize_compressed(&**bytes);
                OTSignatureType::P(signature.unwrap())
            },
        }
    }
}
pub trait OTSignatureScheme<E: Pairing>{
    fn generate_keys(&self) -> (OTSPublicKeyType<E>, OTSSigningKeyType<E>);
}
#[derive(Debug)]
pub enum OTS{
    LD,
    P
}
pub enum OTSignatureSchemeType{
    LD(LDOTSignatureScheme),
    P(POTSignatureScheme),
}

impl OTSignatureSchemeType {
    pub fn generate_keys<E: Pairing>(&self) -> (OTSPublicKeyType<E>, OTSSigningKeyType<E>) 
    {
        match self {
            OTSignatureSchemeType::LD(scheme) => {
                scheme.generate_keys()
            },
            OTSignatureSchemeType::P(scheme) => {
                scheme.generate_keys()
            },
        }
    }
}
pub trait OTSSigningKey<E: Pairing> {
    fn osign(&self, h : &GenericArray<u8, U32>) -> OTSignatureType<E>;
}
pub enum OTSSigningKeyType<E: Pairing> {
    LD(LDOTSSigningKey),
    P(POTSSigningKey<E>),
}
impl<E: Pairing> OTSSigningKeyType<E> {
    pub fn ld_value(&self) -> &LDOTSSigningKey {
        match self {
            OTSSigningKeyType::LD(sk) => sk,
            _ => panic!("Not LD OTSSigningKey"),
        }  
    }    
    pub fn p_value(&self) -> &POTSSigningKey<E> {
        match self {
            OTSSigningKeyType::P(sk) => sk,
            _ => panic!("Not P OTSSigningKey"),
        }   
    }
    pub fn osign(&self, h : &GenericArray<u8, U32>) -> OTSignatureType<E> {
        match self {
            OTSSigningKeyType::LD(sk) => {
                sk.osign(h)
            },
            OTSSigningKeyType::P(sk) => {
                sk.osign(h)
            },
        }
    }
}
pub trait OTSPublicKey<E: Pairing> {
    fn overify(
        &self,
        signature: & OTSignatureType<E>,
        m:&GenericArray<u8, U32>,
        
    ) -> Result<(), SignatureError>;
}
#[derive(Debug,Copy, Clone)]
pub enum OTSPublicKeyType<E: Pairing>{
    LD(LDOTSPublicKey),
    P(POTSPublicKey<E>),
}
impl<E: Pairing> OTSPublicKeyType<E> {
    pub fn overify(&self,signature: &OTSignatureType<E>, m: &GenericArray<u8, U32>) -> Result<(), SignatureError> {
        match self {
            OTSPublicKeyType::LD(pk) => {
                pk.overify(signature, m).unwrap(); //TODO check error handling
            }
            OTSPublicKeyType::P(pk) => {
                pk.overify(signature, m).unwrap(); //TODO check error handling
            }
        };
        Ok(())
    }
    pub fn ld_value(&self) -> &LDOTSPublicKey {
        match self {
            OTSPublicKeyType::LD(pk) => pk,
            _ => panic!("Not LD OTSPublicKey"),
        }
    }
    pub fn p_value(&self) -> &POTSPublicKey<E> {
        match self {
            OTSPublicKeyType::P(pk) => pk,
            _ => panic!("Not P OTSPublicKey"),
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            OTSPublicKeyType::LD(pk) => {
                pk.serialize()
            },
            OTSPublicKeyType::P(pk) => {
                let mut serialized_bytes: Vec<u8> = Vec::new();
                pk.serialize_compressed(&mut serialized_bytes).unwrap();
                serialized_bytes
            },
        }
    }
    pub fn deserialize(bytes: &Vec<u8>, ots: &OTS) -> OTSPublicKeyType<E> {
        match ots {
            OTS::LD => {
                let pk = LDOTSPublicKey::deserialize(bytes);
                OTSPublicKeyType::LD(pk.unwrap())
            },
            OTS::P => {
                let pk = POTSPublicKey::<E>::deserialize_compressed(&**bytes);
                OTSPublicKeyType::P(pk.unwrap())
            },
        }
    }


}

//////////*******************FISCHLIN TRANSFORM*******************//////////

pub fn starts_4_zero_bits(bytes: &[u8]) -> bool {
    bytes[0] & 0xF0 == 0
}

//////////*******************SCHNORR PROOF*******************//////////
/// Schnorr proof
#[derive(Debug)]
pub enum SchnorrProofType<E:Pairing>{
    SchnorrProof(SchnorrProof<E>),
    SchnorrProof2(SchnorrProof2<E>),
}
impl<E:Pairing> SchnorrProofType<E>{
    pub fn schnorr_proof_value(&self) -> &SchnorrProof<E>{
        match self {
            SchnorrProofType::SchnorrProof(proof) => proof,
            _ => panic!("Not SchnorrProof"),
        }
    }
    pub fn schnorr_proof2_value(&self) -> &SchnorrProof2<E>{
        match self {
            SchnorrProofType::SchnorrProof2(proof) => proof,
            _ => panic!("Not SchnorrProof2"),
        }
    }
}

/// Schnorr proof of knowledge of discrete logarithm
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrProof<E:Pairing>{
    pub commitment: Vec<E::G1>,
    pub challenge: Vec<E::ScalarField>,
    pub response: Vec<E::ScalarField>,
}

impl<E:Pairing> SchnorrProof<E>{
    pub fn hash_schnorr( hasher: & mut Sha256, g: &E::G1, pk_ra: &SPSImpPublicKey<E>, gid: &E::G1, pk: &E::G1, commitments: &Vec<E::G1>,)  {
        let mut serialized_bytes: Vec<u8> = Vec::new();
        g.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk1a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk2a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk3a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk4a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk5a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hk6a.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.hka.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.ha.serialize_uncompressed(&mut serialized_bytes).unwrap();
        gid.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk.serialize_uncompressed(&mut serialized_bytes).unwrap();
        for c in commitments {
            c.serialize_uncompressed(&mut serialized_bytes).unwrap();
        }
        hasher.update(&serialized_bytes);
        
    }
    fn hash_b( hasher: & mut Sha256, common_h: &E::ScalarField, lambda: u32, challenge: &E::ScalarField, response: &E::ScalarField,)  {
        let mut serialized_bytes: Vec<u8> = Vec::new();
        common_h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        lambda.serialize_uncompressed(&mut serialized_bytes).unwrap();
        challenge.serialize_uncompressed(&mut serialized_bytes).unwrap();
        response.serialize_uncompressed(&mut serialized_bytes).unwrap();
        hasher.update(&serialized_bytes);
        
    }
    pub fn new(secret: &E::ScalarField, pk_ra: &SPSImpPublicKey<E>, gid: &E::G1, pk: &E::G1) -> Self {
        let mut rng = ark_std::test_rng(); 

        let mut rs: Vec<E::ScalarField> = Vec::new();
        let mut commitments: Vec<E::G1> = Vec::new();
        let mut responses: Vec<E::ScalarField> = Vec::new();
        let mut commitment: E::G1;
        let mut r: E::ScalarField;
        let mut challenges: Vec<E::ScalarField> = Vec::new();
        let mut challenge: E::ScalarField;
        let mut response: E::ScalarField;
        for _ in 0..LAMBDA{
            r = E::ScalarField::rand(&mut rng);
            commitment = E::G1::generator() * r;
            commitments.push(commitment);
            rs.push(r);
        }
        
        let mut hasher = Sha256::new();
        
        Self::hash_schnorr(&mut hasher, &E::G1::generator(), pk_ra, gid, pk, &commitments);
        let h = hasher.finalize();
        let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
        for i in 0..LAMBDA{            
            for e in 0..B_2{
                challenge = E::ScalarField::from(e);
                response = rs[i as usize] + challenge * secret;
                let mut hasher_b = Sha256::new();
                Self::hash_b(&mut hasher_b, &common_h, i, &challenge, &response);
                let hb = hasher_b.finalize();
                if starts_4_zero_bits(&hb){ 
                    challenges.push(challenge);
                    responses.push(response);
                    break;
                }
                
                
            } //TODO change failure handling
        }
        SchnorrProof{
            commitment:commitments,
            challenge: challenges,
            response: responses,
        }
        
    }

    pub fn verify(&self, pk: &E::G1, common_h: &E::ScalarField) -> bool {
        for i in 0..LAMBDA{            
            let i_u = i as usize;
            let challenge = self.challenge[i_u];
            let response = self.response[i_u];
            let left = E::G1::generator() * response;
            let right = self.commitment[i_u] + *pk * challenge;
            if left != right {
                return false;
            }
            let mut hasher_b = Sha256::new();
            Self::hash_b(&mut hasher_b, common_h, i, &challenge, &response);
            let hb = hasher_b.finalize();
            if ! starts_4_zero_bits(&hb){
                return false;
            }
        }
        true
    }
}

//////////*******************SCHNORR PROOF ANONIZE*******************//////////
/// Schnorr proof of knowledge of discrete logarithm
#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SchnorrProof2<E:Pairing>{
    pub commitment: Vec<E::G1>,
    pub challenge: Vec<E::ScalarField>,
    pub response1: Vec<E::ScalarField>,
    pub response2: Vec<E::ScalarField>,
}

impl<E:Pairing> SchnorrProof2<E>{
    pub fn hash_schnorr2( hasher: & mut Sha256, g: &E::G1, pk_ra: &BBPublicKey<E>, gid: &E::G1, alpha:  &E::G1, gamma: &Vec<E::G1>)  {
        let mut serialized_bytes: Vec<u8> = Vec::new();
        g.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.u.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.v.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.e.serialize_uncompressed(&mut serialized_bytes).unwrap();
        gid.serialize_uncompressed(&mut serialized_bytes).unwrap();
        alpha.serialize_uncompressed(&mut serialized_bytes).unwrap();
        for g in gamma {
            g.serialize_uncompressed(&mut serialized_bytes).unwrap();
        }

        hasher.update(&serialized_bytes);
        
    }
    fn hash_b( hasher: & mut Sha256, common_h: &E::ScalarField, lambda: u32, challenge: &E::ScalarField, response1: &E::ScalarField, response2: &E::ScalarField,)  {
        let mut serialized_bytes: Vec<u8> = Vec::new();
        common_h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        lambda.serialize_uncompressed(&mut serialized_bytes).unwrap();
        challenge.serialize_uncompressed(&mut serialized_bytes).unwrap();
        response1.serialize_uncompressed(&mut serialized_bytes).unwrap();
        response2.serialize_uncompressed(&mut serialized_bytes).unwrap();
        hasher.update(&serialized_bytes);
        
    }
    pub fn new(secret1: &E::ScalarField, secret2: &E::ScalarField, v:&E::G1, pk_ra: &BBPublicKey<E>, gid: &E::G1, alpha:  &E::G1) -> Self {
        let mut rng = ark_std::test_rng(); 

        let mut r1s: Vec<E::ScalarField> = Vec::new();
        let mut r2s: Vec<E::ScalarField> = Vec::new();
        let mut commitments: Vec<E::G1> = Vec::new();
        let mut response1s: Vec<E::ScalarField> = Vec::new();
        let mut response2s: Vec<E::ScalarField> = Vec::new();
        let mut commitment: E::G1;
        let mut r1: E::ScalarField;
        let mut r2: E::ScalarField;
        let mut challenges: Vec<E::ScalarField> = Vec::new();
        let mut challenge: E::ScalarField;
        let mut response1: E::ScalarField;
        let mut response2: E::ScalarField;

        for _ in 0..LAMBDA{
            r1 = E::ScalarField::rand(&mut rng);
            r2 = E::ScalarField::rand(&mut rng);

            commitment = *v*r1+E::G1::generator() * r2;
            commitments.push(commitment);
            r1s.push(r1);
            r2s.push(r2);
        }
        
        let mut hasher = Sha256::new();
        
        Self::hash_schnorr2(&mut hasher, &E::G1::generator(), pk_ra, gid, alpha, &commitments);
        let h = hasher.finalize();
        let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
        for i in 0..LAMBDA{            
            response1 = r1s[i as usize];
            response2 = r2s[i as usize];
            for e in 1..B_2{                
                challenge = E::ScalarField::from(e);
                response1 = response1 +secret1;
                response2 = response2 +secret2;
                let mut hasher_b = Sha256::new();
                Self::hash_b(&mut hasher_b, &common_h, i, &challenge, &response1, &response2);
                let hb = hasher_b.finalize();
                if starts_4_zero_bits(&hb){
                    challenges.push(challenge);
                    response1s.push(response1);
                    response2s.push(response2);
                    break;
                }
            }
        }
        
        SchnorrProof2{
            commitment: commitments,
            challenge: challenges,
            response1: response1s,
            response2: response2s,
        }
    }
    
    pub fn verify(&self, alpha: &E::G1, v: &E::G1, common_h: &E::ScalarField) -> bool {

        for i in 0..LAMBDA{            
            let i_u = i as usize;
            let challenge = self.challenge[i_u];
            let response1 = self.response1[i_u];
            let response2 = self.response2[i_u];
            let left = *v*response1 + E::G1::generator() * response2;
            let right = self.commitment[i_u] + *alpha * challenge;
            if left != right {
                return false;
            }
            let mut hasher_b = Sha256::new();
            Self::hash_b(&mut hasher_b, common_h, i, &challenge, &response1, &response2);
            let hb = hasher_b.finalize();
            if ! starts_4_zero_bits(&hb){
                return false;
            }
        }
        true
    }
}

//////////*******************GS PROOF LIBRARY*******************//////////
#[derive(Debug,Clone)]
pub struct CProofCanonical< E: Pairing>(pub CProof<E>);
impl<E:Pairing> ark_serialize::Valid for CProofCanonical<E> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
impl< E: Pairing> CanonicalSerialize for CProofCanonical< E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        let proof = &self.0;

        // Replace with actual fields, in canonical order
        proof.xcoms.serialize_with_mode(&mut writer, compress)?;
        proof.ycoms.serialize_with_mode(&mut writer, compress)?;
        proof.equ_proofs.serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let proof = &self.0;

        proof.xcoms.serialized_size(compress)
            + proof.ycoms.serialized_size(compress)
            + proof.equ_proofs.serialized_size(compress)
    }

}
impl <E: Pairing> CanonicalDeserialize for CProofCanonical< E>{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: Compress,
        validate: ark_serialize::Validate
    ) -> Result<Self, SerializationError> {
        let mut reader = reader;
        // This is a placeholder. In practice, you would read the fields in the same order as they were written.
        let xcoms = Commit1::<E>::deserialize_with_mode(&mut reader, compress,validate)?;
        let ycoms = Commit2::<E>::deserialize_with_mode(&mut reader, compress,validate)?;
        let equ_proofs = Vec::<EquProof<E>>::deserialize_with_mode(&mut reader, compress,validate)?;

        // Construct a CProof from the deserialized fields
        let proof = CProof {
            xcoms,
            ycoms,
            equ_proofs,
        };

        Ok(CProofCanonical(proof))
    }     

}

///Commitment and associated randomness
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Commit1WithRandomness<E: Pairing> {
    pub coms: Vec<Com1<E>>,
    pub rand: Matrix<E::ScalarField>,
}

// Commitment to G1
pub fn commit_g1_with_randomness<CR, E>(xvar: &E::G1Affine, key: &CRSLib<E>, rng: &mut CR) -> Commit1WithRandomness<E>
where
    E: Pairing,
    CR: Rng,
{
    let (r1, r2) = (E::ScalarField::rand(rng), E::ScalarField::rand(rng));

    // c := i_1(x) + r_1 u_1 + r_2 u_2
    Commit1WithRandomness::<E> {
        coms: vec![
            Com1::<E>::linear_map(xvar)
                + vec_to_col_vec(&key.u)[0][0].scalar_mul(&r1)
                + vec_to_col_vec(&key.u)[1][0].scalar_mul(&r2),
        ],
        rand: vec![vec![r1, r2]],
    }
}

//////////*******************USER REGISTRATION*******************//////////

/// Data sent from the user to the RA during registration
/// id: the user identifier in G1
/// pk: the user's public key in G1 related to sid
/// proof: a Schnorr proof of knowledge of the discrete logarithm of pk with respect to sid
#[derive(Debug)]
pub struct UserRAComm {
    pub id: Vec<u8>,//E::G1,
    pub pk: Vec<u8>,//E::G1,
    pub proof: Vec<u8>,//ProofType<E>,
    pub proof_type: Proofs,
}

#[derive(Debug)]
pub struct UserRAComm2 {
    pub signature: Vec<u8>,//SignatureType
    //pub signature_type: Signatures,
}


//////////*******************PROOF*******************//////////
#[derive(Debug,)]
pub enum SubmissionProofCompressed{
    GSLIB(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>), //GS from library
    GS(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), // GS submission implemented
}
impl SubmissionProofCompressed {
    pub fn gslib_value(&self) -> (&Vec<u8>,&Vec<u8>,&Vec<u8>,&Vec<u8>,&Vec<u8>,&Vec<u8>,&Vec<u8>) {
        match self {
            SubmissionProofCompressed::GSLIB(proof1, proof2, proof3, proof4, proof5, proof6, proof7) => (proof1, proof2, proof3, proof4, proof5, proof6, proof7),
            _ => panic!("Not GS proof"),
        }
    }
    pub fn gs_value(&self) -> (&Vec<u8>, &Vec<u8>, &Vec<u8>, &Vec<u8>, &Vec<u8>) {
        match self {
            SubmissionProofCompressed::GS(proof1, proof2, proof3, proof4, proof5) => (proof1, proof2, proof3, proof4, proof5),
            _ => panic!("Not GS proof"),
        }
    }

    pub fn deserialize<E: Pairing>(&self) -> SubmissionProof<E> {
        match self {
            SubmissionProofCompressed::GSLIB(proof1, proof2, proof3, proof4, proof5, proof6, proof7) => 
            {
                let proof1 = CProofCanonical::<E>::deserialize_compressed(&**proof1).unwrap().0;
                let proof2 = CProofCanonical::<E>::deserialize_compressed(&**proof2).unwrap().0;
                let proof3 = CProofCanonical::<E>::deserialize_compressed(&**proof3).unwrap().0;
                let proof4 = CProofCanonical::<E>::deserialize_compressed(&**proof4).unwrap().0;
                let proof5 = CProofCanonical::<E>::deserialize_compressed(&**proof5).unwrap().0;
                let proof6 = CProofCanonical::<E>::deserialize_compressed(&**proof6).unwrap().0;
                let proof7 = CProofCanonical::<E>::deserialize_compressed(&**proof7).unwrap().0;
                SubmissionProof::GSLIB(proof1, proof2, proof3, proof4, proof5, proof6, proof7)
                },
            SubmissionProofCompressed::GS(proof1, proof2, proof3, proof4, proof5) => {
                let proof1 = GSRA11::<E>::deserialize_compressed(&**proof1).unwrap();
                let proof2 = GSRA12::<E>::deserialize_compressed(&**proof2).unwrap();
                let proof3 = GSSA11::<E>::deserialize_compressed(&**proof3).unwrap();
                let proof4 = GSRA12::<E>::deserialize_compressed(&**proof4).unwrap();
                let proof5 = GSSA3::<E>::deserialize_compressed(&**proof5).unwrap();
                SubmissionProof::GS(proof1, proof2, proof3, proof4, proof5)
            },
        }
    }
    
}
#[derive(Debug,)]
pub enum SubmissionProof<E:Pairing>{
    GSLIB(CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>), //GS from library
    GS(GSRA11<E>, GSRA12<E>, GSSA11<E>, GSRA12<E>,GSSA3<E>), // GS submission implemented
}
impl <E:Pairing> SubmissionProof<E>{
    pub fn gslib_value(&self) -> (&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>) {
        match self {
            SubmissionProof::GSLIB(proof1, proof2, proof3, proof4, proof5, proof6, proof7) => (proof1, proof2, proof3, proof4, proof5, proof6, proof7),
            _ => panic!("Not GS proof"),
        }
    }
    pub fn gs_value(&self) -> (&GSRA11<E>, &GSRA12<E>, &GSSA11<E>, &GSRA12<E>, &GSSA3<E>) {
        match self {
            SubmissionProof::GS(proof1, proof2, proof3, proof4, proof5) => (proof1, proof2, proof3, proof4, proof5),
            _ => panic!("Not GS proof"),
        }
    }

    pub fn serialize(&self) -> SubmissionProofCompressed {
        match self {
            SubmissionProof::GSLIB(proof1, proof2, proof3, proof4, proof5, proof6, proof7) => {
                let serialized_proof1={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof1.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof2={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof2.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof3={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof3.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof4={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof4.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof5={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof5.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof6={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof6.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof7={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    CProofCanonical(proof7.clone()).serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                SubmissionProofCompressed::GSLIB(serialized_proof1, serialized_proof2, serialized_proof3, serialized_proof4, serialized_proof5, serialized_proof6, serialized_proof7)

                
            },
            SubmissionProof::GS(proof1, proof2, proof3, proof4, proof5) => {
                let serialized_proof1={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    proof1.serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof2={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    proof2.serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof3={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    proof3.serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof4={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    proof4.serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                let serialized_proof5={
                    let mut serialized_bytes: Vec<u8> = Vec::new();
                    proof5.serialize_compressed(&mut serialized_bytes).unwrap();
                    serialized_bytes
                };
                SubmissionProofCompressed::GS(serialized_proof1, serialized_proof2, serialized_proof3, serialized_proof4, serialized_proof5)
            },
        }
    }
}
pub trait Proof<E:Pairing>{}
impl<E:Pairing> Proof<E> for CProof<E> {}


#[derive(Debug)]
pub enum Proofs{
    GSLIB,
    GS,
    GSProof,
    GSRA,
    AN,
    SC,
    SC2
}
#[derive(Debug)]
pub enum ProofTypeCompressed<E:Pairing>{
    GSLIB(SubmissionProofCompressed),//GS submission proof from library
    GS(SubmissionProofCompressed), // GS submission proof implemented
    GSProof(CProof<E>), //GS from library
    GSRA(GSU<E>), // GS user registration implemented   
    AN(ProofAnonize<E>), // Anonize proof submission
    SC(SchnorrProof<E>), // Schnorr proof user registration implemented
    SC2(SchnorrProof2<E>), // Schnorr proof user registration Anonize
    None
}
impl<E:Pairing> ProofTypeCompressed<E> {
    pub fn gslib_value(&self) -> &SubmissionProofCompressed {
        match self {
            ProofTypeCompressed::GSLIB(proof) => proof, //.gslib_value(),
            _ => panic!("Not GS proof"),
        }
    }
    pub fn gs_value(&self) -> &SubmissionProofCompressed {
        match self {
            ProofTypeCompressed::GS(proof) => proof, //.gs_value(),
            _ => panic!("Not GS proof"),
        }
    }

     pub fn deserialize_gslib(&self) -> SubmissionProof<E> {
        match self {
            ProofTypeCompressed::GSLIB(proof) => proof.deserialize(),
            _ => panic!("Not GS proof"),
        }
    }
}
#[derive(Debug)]
pub enum ProofType<E:Pairing>{
    GSLIB(SubmissionProof<E>),//GS submission proof from library
    GS(SubmissionProof<E>), // GS submission proof implemented
    GSProof(CProof<E>), //GS from library
    GSRA(GSU<E>), // GS user registration implemented   
    AN(ProofAnonize<E>), // Anonize proof submission
    SC(SchnorrProof<E>), // Schnorr proof user registration implemented
    SC2(SchnorrProof2<E>), // Schnorr proof user registration Anonize
    None
}
impl<E:Pairing> ProofType<E> {

    pub fn gs_value(&self) -> (&GSRA11<E>, &GSRA12<E>, &GSSA11<E>, &GSRA12<E>, &GSSA3<E>) {
        match self {
            ProofType::GS(proof) => proof.gs_value(),
            _ => panic!("Not GS proof"),
        }
    }
    pub fn gslib_value(&self) -> (&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>,&CProof<E>) {
        match self {
            ProofType::GSLIB(proof) => proof.gslib_value(),
            _ => panic!("Not GS proof"),
        }
    }
    pub fn an_value(&self) -> &ProofAnonize<E> {
        match self {
            ProofType::AN(proof) => proof,
            _ => panic!("Not AN proof"),
        }
    }
    pub fn gsu_value(&self) -> &GSU<E> {
        match self {
            ProofType::GSRA(proof) => proof,
            _ => panic!("Not GSU proof"),
        }
    }

    pub fn sc_value(&self) -> &SchnorrProof<E> {
        match self {
            ProofType::SC(proof) => proof,
            _ => panic!("Not Schnorr proof"),
        }
    }
    pub fn sc2_value(&self) -> &SchnorrProof2<E> {
        match self {
            ProofType::SC2(proof) => proof,
            _ => panic!("Not Schnorr proof 2"), 
        }
    }
}
/// Proof submission Anonize
#[derive(Debug)]
pub struct ProofAnonizeCompressed{
    pub e1: Vec<Vec<u8>>,
    pub e2: Vec<Vec<u8>>,
    pub e3: Vec<Vec<u8>>,
    pub challenge: Vec<Vec<u8>>,
    pub z1: Vec<Vec<u8>>,
    pub z2: Vec<Vec<u8>>,
    pub z3: Vec<Vec<u8>>,
    pub z4: Vec<Vec<u8>>,
}
impl ProofAnonizeCompressed {
    pub fn deserialize<E: Pairing>(&self) -> ProofAnonize<E> {
        let mut e1: Vec<E::TargetField> = Vec::new();
        let mut e2: Vec<E::TargetField> = Vec::new();
        let mut e3: Vec<E::TargetField> = Vec::new();
        let mut challenge: Vec<E::ScalarField> = Vec::new();
        let mut z1: Vec<E::ScalarField> = Vec::new();
        let mut z2: Vec<E::ScalarField> = Vec::new();
        let mut z3: Vec<E::G1> = Vec::new();
        let mut z4: Vec<E::G1> = Vec::new();

        for bytes in &self.e1 {
            e1.push(E::TargetField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.e2 {
            e2.push(E::TargetField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.e3 {
            e3.push(E::TargetField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.challenge {
            challenge.push(E::ScalarField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.z1 {
            z1.push(E::ScalarField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.z2 {
            z2.push(E::ScalarField::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.z3 {
            z3.push(E::G1::deserialize_compressed(&**bytes).unwrap());
        }
        for bytes in &self.z4 {
            z4.push(E::G1::deserialize_compressed(&**bytes).unwrap());
        }

        ProofAnonize{
            e1,
            e2,
            e3,
            challenge,
            z1,
            z2,
            z3,
            z4,
        }
    }
}
#[derive(Debug)]
pub struct ProofAnonize<E:Pairing>{
    pub e1: Vec<E::TargetField>,
    pub e2: Vec<E::TargetField>,
    pub e3: Vec<E::TargetField>,
    pub challenge: Vec<E::ScalarField>,
    pub z1: Vec<E::ScalarField>,
    pub z2: Vec<E::ScalarField>,
    pub z3: Vec<E::G1>,
    pub z4: Vec<E::G1>,
}
impl<E:Pairing> ProofAnonize<E>  {
    pub fn serialize(&self)->ProofAnonizeCompressed{
        let mut e1_bytes: Vec<Vec<u8>> = Vec::new();
        let mut e2_bytes: Vec<Vec<u8>> = Vec::new();
        let mut e3_bytes: Vec<Vec<u8>> = Vec::new();
        let mut challenge_bytes: Vec<Vec<u8>> = Vec::new();
        let mut z1_bytes: Vec<Vec<u8>> = Vec::new();
        let mut z2_bytes: Vec<Vec<u8>> = Vec::new();
        let mut z3_bytes: Vec<Vec<u8>> = Vec::new();
        let mut z4_bytes: Vec<Vec<u8>> = Vec::new();

        for e in &self.e1 {
            let mut bytes: Vec<u8> = Vec::new();
            e.serialize_compressed(&mut bytes).unwrap();
            e1_bytes.push(bytes);
        }
        for e in &self.e2 {
            let mut bytes: Vec<u8> = Vec::new();
            e.serialize_compressed(&mut bytes).unwrap();
            e2_bytes.push(bytes);
        }
        for e in &self.e3 {
            let mut bytes: Vec<u8> = Vec::new();
            e.serialize_compressed(&mut bytes).unwrap();
            e3_bytes.push(bytes);
        }
        for c in &self.challenge {
            let mut bytes: Vec<u8> = Vec::new();
            c.serialize_compressed(&mut bytes).unwrap();
            challenge_bytes.push(bytes);
        }
        for z in &self.z1 {
            let mut bytes: Vec<u8> = Vec::new();
            z.serialize_compressed(&mut bytes).unwrap();
            z1_bytes.push(bytes);
        }
        for z in &self.z2 {
            let mut bytes: Vec<u8> = Vec::new();
            z.serialize_compressed(&mut bytes).unwrap();
            z2_bytes.push(bytes);
        }
        for z in &self.z3 {
            let mut bytes: Vec<u8> = Vec::new();
            z.serialize_compressed(&mut bytes).unwrap();
            z3_bytes.push(bytes);
        }
        for z in &self.z4 {
            let mut bytes: Vec<u8> = Vec::new();
            z.serialize_compressed(&mut bytes).unwrap();
            z4_bytes.push(bytes);
        }

        ProofAnonizeCompressed{
            e1: e1_bytes,
            e2: e2_bytes,
            e3: e3_bytes,
            challenge: challenge_bytes,
            z1: z1_bytes,
            z2: z2_bytes,
            z3: z3_bytes,
            z4: z4_bytes,
        }
    }
    fn hash_b( hasher: & mut Sha256, common_h: &E::ScalarField, lambda: u32, challenge: &E::ScalarField, z1: &E::ScalarField, 
            z2: &E::ScalarField, z3: &E::G1, z4: &E::G1,)  {
        let mut serialized_bytes: Vec<u8> = Vec::new();
        common_h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        lambda.serialize_uncompressed(&mut serialized_bytes).unwrap();
        challenge.serialize_uncompressed(&mut serialized_bytes).unwrap();
        z1.serialize_uncompressed(&mut serialized_bytes).unwrap();
        z2.serialize_uncompressed(&mut serialized_bytes).unwrap();
        z3.serialize_uncompressed(&mut serialized_bytes).unwrap();
        z4.serialize_uncompressed(&mut serialized_bytes).unwrap();
        hasher.update(&serialized_bytes);
        
    }
    fn hash_anonize(hasher: &mut Sha256, g: &E::G1, pk_ra: &BBPublicKey<E>, pk_sa: &BBPublicKey<E>, 
        s2: &E::G2, s4: &E::G2,
        e1: &Vec<E::TargetField>, e2: &Vec<E::TargetField>, e3: &Vec<E::TargetField>,
        ){ 
        let mut serialized_bytes: Vec<u8> = Vec::new();
        g.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.u.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.v.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_ra.e.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_sa.u.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_sa.v.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_sa.h.serialize_uncompressed(&mut serialized_bytes).unwrap();
        pk_sa.e.serialize_uncompressed(&mut serialized_bytes).unwrap();        
        s2.serialize_uncompressed(&mut serialized_bytes).unwrap();
        s4.serialize_uncompressed(&mut serialized_bytes).unwrap();
        for e in e1 {
            e.serialize_uncompressed(&mut serialized_bytes).unwrap();
        }
        for e in e2 {
            e.serialize_uncompressed(&mut serialized_bytes).unwrap();
        }
        for e in e3 {
            e.serialize_uncompressed(&mut serialized_bytes).unwrap();
        }
        hasher.update(&serialized_bytes);
    }
    pub fn new(id: &E::ScalarField,sid: &E::ScalarField, pk_ra: &BBPublicKey<E>, pk_sa: &BBPublicKey<E>, s1: &E::G1, s2: &E::G2, s3: &E::G1, s4: &E::G2, token: &E::TargetField) -> Result<Self, FischlinError> {
        let mut rng = ark_std::test_rng();
    
        let g2 = E::G2::generator();

        let mut b1: E::ScalarField;
        let mut b2: E::ScalarField;
        let mut j1: E::G1;
        let mut j2: E::G1;
        let mut j1s: Vec<E::G1> = Vec::new();
        let mut j2s: Vec<E::G1> = Vec::new();
        let mut b1s: Vec<E::ScalarField> = Vec::new();
        let mut b2s: Vec<E::ScalarField> = Vec::new();
        let mut e1: E::TargetField;
        let mut e2: E::TargetField;
        let mut e3: E::TargetField;
        let mut e1s: Vec<E::TargetField> = Vec::new();
        let mut e2s: Vec<E::TargetField> = Vec::new();
        let mut e3s: Vec<E::TargetField> = Vec::new();
        let mut z1: E::ScalarField;
        let mut z2: E::ScalarField;
        let mut z3: E::G1;
        let mut z4: E::G1;
        let mut z1s: Vec<E::ScalarField> = Vec::new();
        let mut z2s: Vec<E::ScalarField> = Vec::new();
        let mut z3s: Vec<E::G1> = Vec::new();
        let mut z4s: Vec<E::G1> = Vec::new();
        let mut challenges: Vec<E::ScalarField> = Vec::new();
        let mut challenge: E::ScalarField;

        for _ in 0..LAMBDA {
            b1 = E::ScalarField::rand(&mut rng);
            b2 = E::ScalarField::rand(&mut rng);
            j1 = E::G1::rand(&mut rng);
            j2 = E::G1::rand(&mut rng);

            e1 = (E::pairing(j1, g2)- E::pairing(pk_ra.u*b1 + pk_ra.v*b2,s2)).0;
            e2 = (E::pairing(j2,g2) - E::pairing(pk_sa.v*b1,s4)).0; 
            e3 = (GT::<E>(*token)*b2).0;
            e1s.push(e1);
            e2s.push(e2);
            e3s.push(e3);
            j1s.push(j1);
            j2s.push(j2);
            b1s.push(b1);
            b2s.push(b2);
        }
        let mut hasher = Sha256::new();
        
        Self::hash_anonize(&mut hasher, &E::G1::generator(), pk_ra,pk_sa,
                                 &s2, &s4,
                                &e1s, &e2s, &e3s);
        let h = hasher.finalize();
        let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
        let mut i_u: usize;
        for i in 0..LAMBDA {
            i_u = i as usize;
            z1=b1s[i_u];
            z2=b2s[i_u];
            z3=j1s[i_u];
            z4=j2s[i_u];
            for e in 1..B_2 {
                challenge = E::ScalarField::from(e);
                z1 = z1+id;
                z2 = z2+sid;
                z3 = z3+*s1;
                z4 = z4+*s3;
                
                let mut hasher_b = Sha256::new();
                Self::hash_b(&mut hasher_b, &common_h, i, &challenge, &z1, &z2, &z3, &z4);
                let hb = hasher_b.finalize();
                if starts_4_zero_bits(&hb){
                    challenges.push(challenge);
                    z1s.push(z1);
                    z2s.push(z2);
                    z3s.push(z3);
                    z4s.push(z4);
                    break;
                    
                }
                if e==B_2-1{
                        return Err(FischlinError::ZeroFailure);
                    }
            
             //TODO change failure handling
            }
        }

        Ok(ProofAnonize{
                e1:e1s,
                e2:e2s,
                e3:e3s,
                challenge:challenges,
                z1:z1s,
                z2:z2s,
                z3:z3s,
                z4:z4s,
        })
    }
    pub fn verify(&self,s2: &E::G2,s4:&E::G2, pk_ra: &BBPublicKey<E>, pk_sa: &BBPublicKey<E>, vid: &E::ScalarField, token:&E::TargetField) -> bool {
        let mut hasher = Sha256::new();
        Self::hash_anonize(&mut hasher, &E::G1::generator(), pk_ra,pk_sa,
                                 &s2, &s4,
                                &self.e1, &self.e2, &self.e3);
        let h = hasher.finalize();
        let common_h = E::ScalarField::from_le_bytes_mod_order(&h);
        let mut c: E::ScalarField;
        let mut i_u:usize;
        let g = E::G1::generator();
        let g2 = E::G2::generator();
        for i in 0..LAMBDA {
            i_u = i as usize;
            c = self.challenge[i_u];
            
            let left1 = GT(self.e1[i_u]) + pk_ra.e*c+E::pairing(pk_ra.h,s2)*c;
            let right1 = E::pairing(self.z3[i_u], g2)-E::pairing(pk_ra.u*self.z1[i_u] + pk_ra.v*self.z2[i_u], s2);
            if left1 != right1 {
                return false;
            }
            let left2 = GT(self.e2[i_u]) + pk_sa.e*c+E::pairing(pk_sa.u*vid+pk_sa.h, s4)*c;
            let right2 = E::pairing(self.z4[i_u], g2)-E::pairing(pk_sa.v*self.z1[i_u], s4);
            if left2 != right2 {
                return false;
            }
            let left3 = GT(self.e3[i_u])+E::pairing(g, g2)*c - GT(*token)*(c*vid);
            let right3 = GT(*token)*self.z2[i_u];
            if left3 != right3 {
                return false;
            }

            let mut hasher_b = Sha256::new();
            Self::hash_b(&mut hasher_b, &common_h, i, &c, &self.z1[i_u], &self.z2[i_u], &self.z3[i_u], &self.z4[i_u]);
            let hb = hasher_b.finalize();
            if ! starts_4_zero_bits(&hb){
                return false;
            }

        }

        true
    }
}

#[derive(Debug)]
pub enum SubmissionType<E:Pairing>{
    AS(SubmissionCompressed<E>), 
    AN(SubmissionAnonize<E>),
    None
}
impl<E:Pairing> SubmissionType<E> {
    pub fn as_value(&self) -> &SubmissionCompressed<E> {
        match self {
            SubmissionType::AS(submission) => submission,
            _ => panic!("Not AS submission"),
        }
    }
    pub fn an_value(&self) -> &SubmissionAnonize<E> {
        match self {
            SubmissionType::AN(submission) => submission,
            _ => panic!("Not AN submission"),   
        }
    }
}

#[derive(Debug)]
pub enum CommitmentType<E:Pairing>{
    GSLIB(Commit1WithRandomness<E>),
    GS(CommitmentG1<E>),
    None
}
impl <E:Pairing> CommitmentType<E> {
    pub fn gs_value(&self) -> &CommitmentG1<E> {
        match self {
            CommitmentType::GS(commitment) => commitment,
            _ => panic!("Not GS commitment"),
        }
    }
    pub fn gslib_value(&self) -> &Commit1WithRandomness<E> {
        match self {
            CommitmentType::GSLIB(commitment) => commitment,
            _ => panic!("Not GS library commitment"),
        }
    }
    
}

//////////*******************SUBMISSION*******************//////////
#[derive(Debug)]
pub struct SubmissionCompressed<E:Pairing>{
    pub pk_commitment:  Vec<u8>,//Commit1WithRandomness<E>,
    pub token: Vec<u8>,//E::G1,
    pub proof: ProofTypeCompressed<E>, // Vec of compressed proofs
    pub ovk: Vec<u8>, // Vec of compressed OTSPublicKeyTypes
    pub ots: Vec<u8>, // Vec of compressed OTSignatureTypes
    pub ots_type: OTS,
}
impl<E:Pairing> SubmissionCompressed<E> {
    pub fn deserialize(&self, proof_type: &Proofs) -> Submission<E> {
        let pk_commitment= match proof_type {
            Proofs::GSLIB => CommitmentType::GSLIB(Commit1WithRandomness::<E>::deserialize_compressed(&*self.pk_commitment).unwrap()),
            Proofs::GS => CommitmentType::GS(CommitmentG1::<E>::deserialize_compressed(&*self.pk_commitment).unwrap()),
            _ => panic!("Unsupported proof type for deserialization"),
        };
        let token = E::G1::deserialize_compressed(&*self.token).unwrap();
        let proof = match proof_type{
            Proofs::GSLIB => {
                let p = self.proof.gslib_value();
                ProofType::GSLIB(p.deserialize())
            },
            Proofs::GS => {
                let p = self.proof.gs_value();
                ProofType::GS(p.deserialize())
            },
            _ => panic!("Unsupported proof type for deserialization"),
        };
        let ovk = OTSPublicKeyType::deserialize(&self.ovk, &self.ots_type);
        let ots= OTSignatureType::deserialize(&self.ots, &self.ots_type);

        
        // Similarly, deserialize other fields like pk_commitment, ovk, ots as needed.
        Submission {
            pk_commitment,
            token,
            proof,
            ovk: ovk,
            ots: ots,
        }
    }
}
/// Data sent from the user to the survey authority during submission
/// pk_commitment: commitment to the user's public key 
/// token: the unique token generated as a function of vid and sid
/// proof_ra1: proof that the user knows a valid signature from the RA
/// proof_ra2: proof that the user knows a valid signature from the RA
/// proof_sa1: proof that the user knows a valid signature from the SA
/// proof_sa2: proof that the user knows a valid signature from the SA
/// proof_token11: proof that the pk_commitment is correctly formed (part 1)
/// proof_token12: proof that the pk_commitment is correctly formed (part 2)
/// proof_token2: proof that the token is correctly formed 
#[derive(Debug)]
pub struct Submission<E:Pairing>{
    pub pk_commitment:  CommitmentType<E>,
    pub token: E::G1,
    pub proof: ProofType<E>,
    pub ovk: OTSPublicKeyType<E>,
    pub ots: OTSignatureType<E>
}

impl<E: Pairing> Submission<E> {
    pub fn hash1( vid: &E::ScalarField)-><E as Pairing>::G1Affine where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1> {
        let g1_mapper = MapToCurveBasedHasher::<
            E::G1,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Config>,
        >::new(DOMAIN)
        .unwrap();
        g1_mapper.hash(vid.to_string().as_bytes()).unwrap()
    }
    pub fn hash2( vid: &E::ScalarField, ovk: &OTSPublicKeyType<E>)->(<E as Pairing>::G2Affine, <E as Pairing>::G2Affine) where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2> {
        
        let mut hasher = Sha256::new();
        hasher.update(vid.to_string().as_bytes());
        
        match ovk {
            OTSPublicKeyType::LD(ovk_ld) => {
                for i in 0..256 {
                    hasher.update(ovk_ld.vec[i][0]);
                    hasher.update(ovk_ld.vec[i][1]);
                }
            },
            OTSPublicKeyType::P(ovk_p) =>{
                let mut serialized_bytes: Vec<u8> = Vec::new();
                ovk_p.vk_1.serialize_compressed(&mut serialized_bytes).unwrap();
                ovk_p.vk_2.serialize_compressed(&mut serialized_bytes).unwrap();
                ovk_p.hk.serialize_compressed(&mut serialized_bytes).unwrap();
                hasher.update(&serialized_bytes);
            }
    
        }
        let f = hasher.finalize();
        let g2_mapper = MCCH::<
            E::G2,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G2Config>,
        >::new(DOMAIN)
        .unwrap();
        g2_mapper.hash2(f.as_ref()).unwrap()
    }
    pub fn hash3(vid: &E::ScalarField, token: &E::G1,pk_commitment: &CommitmentG1<E>, proof_ra1:&GSRA11<E>, proof_ra2: &GSRA12<E>, 
             proof_sa1:&GSSA11<E>, proof_sa2: &GSRA12<E>, proof_exp: &GSSA3<E>)->GenericArray<u8, U32> {
        let mut hasher = Sha256::new();
        hasher.update(vid.to_string().as_bytes());
        hasher.update("message".as_bytes());
        hasher.update(token.to_string().as_bytes());
        let mut bytes_pk_commitment: Vec<u8> = Vec::new();
        pk_commitment.serialize_compressed(&mut bytes_pk_commitment).unwrap();
        hasher.update(bytes_pk_commitment);
        let mut bytes_proof_ra1: Vec<u8> = Vec::new();
        proof_ra1.serialize_compressed(&mut bytes_proof_ra1).unwrap();
        hasher.update(bytes_proof_ra1);
        let mut bytes_proof_ra2: Vec<u8> = Vec::new();
        proof_ra2.serialize_compressed(&mut bytes_proof_ra2).unwrap();
        hasher.update(bytes_proof_ra2);
        let mut bytes_proof_sa1: Vec<u8> = Vec::new();
        proof_sa1.serialize_compressed(&mut bytes_proof_sa1).unwrap();
        hasher.update(bytes_proof_sa1);
        let mut bytes_proof_sa2: Vec<u8> = Vec::new();
        proof_sa2.serialize_compressed(&mut bytes_proof_sa2).unwrap();
        hasher.update(bytes_proof_sa2);
        let mut bytes_proof_exp: Vec<u8> = Vec::new();
        proof_exp.serialize_compressed(&mut bytes_proof_exp).unwrap();
        hasher.update(bytes_proof_exp);
        hasher.finalize()
    }
    pub fn hash3_gslib(vid: &E::ScalarField, token: &E::G1,pk_commitment: &Commit1WithRandomness<E>, proof_ra1:&CProofCanonical<E>, proof_ra2: &CProofCanonical<E>, 
             proof_sa1:&CProofCanonical<E>, proof_sa2: &CProofCanonical<E>, proof_token11: &CProofCanonical<E>, proof_token12: &CProofCanonical<E>, proof_token2: &CProofCanonical<E>)->GenericArray<u8, U32> {
        let mut hasher = Sha256::new();
        hasher.update(vid.to_string().as_bytes());
        hasher.update("message".as_bytes());
        hasher.update(token.to_string().as_bytes());
        let mut bytes_pk_commitment: Vec<u8> = Vec::new();
        pk_commitment.serialize_compressed(&mut bytes_pk_commitment).unwrap();
        hasher.update(bytes_pk_commitment);
        let mut bytes_proof_ra1: Vec<u8> = Vec::new();
        proof_ra1.serialize_compressed(&mut bytes_proof_ra1).unwrap();
        hasher.update(bytes_proof_ra1);
        let mut bytes_proof_ra2: Vec<u8> = Vec::new();
        proof_ra2.serialize_compressed(&mut bytes_proof_ra2).unwrap();
        hasher.update(bytes_proof_ra2);
        let mut bytes_proof_sa1: Vec<u8> = Vec::new();
        proof_sa1.serialize_compressed(&mut bytes_proof_sa1).unwrap();
        hasher.update(bytes_proof_sa1);
        let mut bytes_proof_sa2: Vec<u8> = Vec::new();
        proof_sa2.serialize_compressed(&mut bytes_proof_sa2).unwrap();
        hasher.update(bytes_proof_sa2);
        let mut bytes_proof_token11: Vec<u8> = Vec::new();
        proof_token11.serialize_compressed(&mut bytes_proof_token11).unwrap();
        hasher.update(bytes_proof_token11);
        let mut bytes_proof_token12: Vec<u8> = Vec::new();
        proof_token12.serialize_compressed(&mut bytes_proof_token12).unwrap();
        hasher.update(bytes_proof_token12);
        let mut bytes_proof_token2: Vec<u8> = Vec::new();
        proof_token2.serialize_compressed(&mut bytes_proof_token2).unwrap();
        hasher.update(bytes_proof_token2);
        hasher.finalize()
    }
}

#[derive(Debug)]
pub struct SubmissionAnonizeCompressed{
    pub token: Vec<u8>,
    pub s2: Vec<u8>,
    pub s4: Vec<u8>,    
    pub proof: ProofAnonizeCompressed,
}
impl SubmissionAnonizeCompressed{
    pub fn deserialize<E: Pairing>(&self) -> SubmissionAnonize<E> {
        let token = E::TargetField::deserialize_uncompressed(&*self.token).unwrap();
        let s2 = E::G2::deserialize_compressed(&*self.s2).unwrap();
        let s4 = E::G2::deserialize_compressed(&*self.s4).unwrap();
        let proof = self.proof.deserialize();
        SubmissionAnonize{
            token,
            s2,
            s4,
            proof,
        }
    }
}
#[derive(Debug)]
pub struct SubmissionAnonize<E:Pairing>{
    pub token: E::TargetField,
    pub s2: E::G2,
    pub s4: E::G2,    
    pub proof: ProofAnonize<E>,
}
impl<E:Pairing> SubmissionAnonize<E> {
    pub fn serialize(&self) -> SubmissionAnonizeCompressed {
        let mut token_bytes: Vec<u8> = Vec::new();
        self.token.serialize_uncompressed(&mut token_bytes).unwrap();
        let mut s2_bytes: Vec<u8> = Vec::new();
        self.s2.serialize_compressed(&mut s2_bytes).unwrap();
        let mut s4_bytes: Vec<u8> = Vec::new();
        self.s4.serialize_compressed(&mut s4_bytes).unwrap();
        SubmissionAnonizeCompressed{
            token: token_bytes,
            s2: s2_bytes,
            s4: s4_bytes,
            proof: self.proof.serialize(),
        }
    }
}
//////////*******************CRS*******************//////////
#[derive(Debug,Clone)]
pub enum CRS<E: Pairing>{
    GS1(CrsG1<E>),
    GS2(CrsG2<E>),
    GSLIB(CRSLib<E>),
    None
}
impl<E:Pairing> CRS<E>{
    pub fn gs1_value(&self) -> &CrsG1<E> {
        match self {
            CRS::GS1(crs) => crs,
            _ => panic!("Not GS1 CRS"),
        }
    }
    pub fn gs2_value(&self) -> &CrsG2<E> {
        match self {
            CRS::GS2(crs) => crs,
            _ => panic!("Not GS2 CRS"),
        }
    }
    pub fn gslib_value(&self) -> &CRSLib<E> {
        match self {
            CRS::GSLIB(crs) => crs,
            _ => panic!("Not GS LIB CRS"),
        }
    }
}
#[derive(Debug)]
pub enum CRStype{
    GS,
    GSLIB,
    AN,
    None
}

pub enum Group{
    G1,
    G2,
    None
}
pub fn generate_crs<E:Pairing, CR: Rng>(mut rng: &mut CR,crs_type: &CRStype, group:&Group) -> CRS<E> {
    match crs_type {
        CRStype::AN => {
            CRS::None
        },
        CRStype::GS => {
            match group {
                Group::G1 => CrsG1::<E>::new(&mut rng),
                Group::G2 => CrsG2::<E>::new(&mut rng),
                Group::None => CRS::None,
            }
            
        },
        CRStype::GSLIB => {
            let c=CRSLib::<E>::generate_crs(&mut rng);
            CRS::GSLIB(c)
        },
        CRStype::None => CRS::None,
    }
}
pub fn setup<E:Pairing,CR>(scheme: &str, ur_proof_type: &str, submission_proof_type: &str, rng: &mut CR) ->(SignatureSchemeType, CRS<E>, CRStype, Group, Group) where CR:Rng {

    if scheme == "AS" {
        let signature_scheme_type = SignatureSchemeType::SPSImp(SPSImpSignatureScheme{});

        let crs_ur: CRS<E> ;
        if ur_proof_type == "SC"{
            crs_ur=  CRS::None;// UR with Schnorr
        }else if ur_proof_type == "GS" {            
            crs_ur =CrsG2::<E>::new(rng);// UR with GS implemented            
        }else if ur_proof_type == "GSLIB" {
            crs_ur = CRS::GSLIB(CRSLib::<E>::generate_crs( rng)); //UR with GS from library
        }else {
            panic!("Please provide a valid user registration proof type: Schnorr, GS, GSLIB");
        }
        let crs_type:CRStype;
        if submission_proof_type == "GSLIB"{
            crs_type = CRStype::GSLIB; //GSLIB for GS from library
        }else if submission_proof_type == "GS" {
            crs_type = CRStype::GS; // GS for GS implemented
        }else {
            panic!("Please provide a valid submission proof type: GS, GSLIB");
        }       
        let group1 = Group::G1;
        let group2 = Group::G2;
        (signature_scheme_type, crs_ur,crs_type, group1, group2)
    }else if scheme == "AN" {
        let signature_scheme_type = SignatureSchemeType::BB(BBSignatureScheme{});
        let crs_type = CRStype::AN;
        //let crs_ur = CRS::None; 
        let group1 = Group::None;
        let group2 = Group::None;
        (signature_scheme_type, CRS::None, crs_type, group1, group2)
    }else {
        panic!("Please provide a valid signature scheme: AS or AN");
    }
}
#[cfg(test)]
 mod tests {
    use super::*;
    use ark_bls12_381::{
        Bls12_381, G1Projective as G1, G2Projective as G2,
        Fr as ScalarField,};
    use ark_ff::{Zero};
     #[test]
     fn an_test(){
            let mut rng = ark_std::test_rng();
            let id = ScalarField::rand(&mut rng);
            let sid = ScalarField::rand(&mut rng);
            let vid = ScalarField::rand(&mut rng);
            let signature_scheme_type: SignatureSchemeType = SignatureSchemeType::BB(BBSignatureScheme{});
            
            let (pk_ra, sk_ra) = signature_scheme_type.bb_value().generate_keys(&ScalarField::rand(&mut rng));
            let (pk_sa, sk_sa) = signature_scheme_type.bb_value().generate_keys(&ScalarField::rand(&mut rng));
            let pk_ra = pk_ra.bb_value();
            let pk_sa = pk_sa.bb_value();
            let uid = pk_ra.u*id;
            let vvid = pk_sa.v*id;
            let uvid = pk_ra.u*vid ;
            let d: ScalarField = ScalarField::rand(&mut rng);
            let alpha =pk_ra.v*sid+G1::generator()*d;
            let signature_ra = SigningKeyType::signature(&sk_ra, &mut rng,&uid, &alpha); 
            let signature_sa = SigningKeyType::signature(&sk_sa, &mut rng,&uvid, &vvid);
            let signature_ra = signature_ra.bb_value();
            let s1_ra = signature_ra.s1 -(signature_ra.s3*d);
            let s2_ra = signature_ra.s2;
            let s3_ra= G1::zero();
            let signature_ra=BBSignature::<Bls12_381>{
                s1: s1_ra,
                s2: s2_ra,
                s3: s3_ra,
            };
            
            let signature_sa = signature_sa.bb_value();
            
            let d1 = ScalarField::rand(&mut rng);
            let d2 = ScalarField::rand(&mut rng);
            let g2 = G2::generator();
            let vsid = pk_ra.v*sid;
            
            let s1 = signature_ra.s1 +(uid + vsid+pk_ra.h )*d1;
            let s2 = signature_ra.s2 + g2*d1;
            let s3 = signature_sa.s1 + (pk_sa.u*vid + pk_sa.v*id+pk_sa.h) *d2;
            let s4 = signature_sa.s2 + g2*d2; 
            let token = Bls12_381::pairing(G1::generator(), G2::generator())*(ScalarField::from(1)/(sid+vid));
            let proof = ProofAnonize::<Bls12_381>::new(&id, &sid, &pk_ra, &pk_sa, &s1, &s2, &s3, &s4, &token.0);
            assert!(proof.unwrap().verify(&s2, &s4, &pk_ra, &pk_sa, &vid, &token.0));
     }
     #[test]
     fn schnorr_test() {
         let mut rng = ark_std::test_rng();
         let secret = ScalarField::rand(&mut rng);
         let pk = G1::generator() * secret;
         let (pk_ra, _trapdoor) = SPSImpPublicKey::<Bls12_381>::new();
         let proof = SchnorrProof::<Bls12_381>::new(&secret,
                                                                            &pk_ra,
                                                                            &G1::generator(),
                                                                            &pk   );
         let mut hasher = Sha256::new();

         SchnorrProof::<Bls12_381>::hash_schnorr(&mut hasher, &G1::generator(), &pk_ra, &G1::generator(), &pk, &proof.commitment);
        let h = hasher.finalize();
        let common_h = ScalarField::from_le_bytes_mod_order(&h);
         assert!(proof.verify(&pk, &common_h));
     }
     #[test]
     fn schnorr_2test() {
         let mut rng = ark_std::test_rng();
         let secret1 = ScalarField::rand(&mut rng);
         let secret2 = ScalarField::rand(&mut rng);
         let v = G1::generator()*ScalarField::from(4);
         let alpha =v*secret1+ G1::generator() * secret2;
         
         let proof = SchnorrProof2::<Bls12_381>::new(&secret1, &secret2,&v, 
                                                                            &BBPublicKey::<Bls12_381>{
                                                                                u: G1::generator()*ScalarField::from(2),
                                                                                v: G1::generator()*ScalarField::from(3),
                                                                                h: G1::generator()*ScalarField::from(5),
                                                                                e: Bls12_381::pairing(G1::generator(), G2::generator())*ScalarField::from(7),
                                                                            },
                                                                            &G1::generator(),
                                                                            &alpha   );
         let mut hasher = Sha256::new();

         SchnorrProof2::<Bls12_381>::hash_schnorr2(&mut hasher, &G1::generator(), &BBPublicKey::<Bls12_381>{
                                                                                u: G1::generator()*ScalarField::from(2),
                                                                                v: G1::generator()*ScalarField::from(3),
                                                                                h: G1::generator()*ScalarField::from(5),
                                                                                e: Bls12_381::pairing(G1::generator(), G2::generator())*ScalarField::from(7),
                                                                            }, &G1::generator(), &alpha, &proof.commitment);
        let h = hasher.finalize();
        let common_h = ScalarField::from_le_bytes_mod_order(&h);
         assert!(proof.verify(&alpha, &v, &common_h));
     }
 }




