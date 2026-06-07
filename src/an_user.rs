use ark_ec::{ pairing::Pairing,     
    PrimeGroup,
};
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, rand::Rng};


use crate::{utils::errors::*};
use crate::utils::utils::{CRS, OTSignatureSchemeType, ProofAnonize, Proofs, PublicKeyType, SchnorrProof2, SignatureType, SubmissionAnonize,SubmissionType, UserRAComm, UserTrait};
use crate::utils::signature::pbbb::{BBSignature};


///User 
/// 'id' : user identifier in G1
/// 'sid' : user secret PRF seed in Fr
/// 'pk' : pk assocated to sid in G1
/// 'pk_ra' : registration authority's signature public key 
/// 'pk_sa' : survey authority's signature public key
/// 'vid' : survey identifier in G1
/// 'signature_ra' : registration authority's signature on (id, pk)
/// 'signature_sa' : survey authority's signature on (id, vid)
#[derive(Copy, Clone)]
pub struct UserAN<'a,E:Pairing>{
    id: E::ScalarField,
    uid: E::G1,
    vvid: E::G1,
    sid: E::ScalarField,
    vsid: E::G1,
    d: E::ScalarField,
    alpha: E::G1,
    pk_ra: &'a PublicKeyType<E>,
    pk_sa: &'a PublicKeyType<E>, //TODO make it a dictionary
    vid: &'a E::ScalarField,
    signature_ra: Option<SignatureType<E>>,
    signature_sa: Option<&'a SignatureType<E>>,
}
impl<'a, E:Pairing> UserAN<'a, E>{
    pub fn new<R:Rng>(rng: &mut R, pk_ra: &'a PublicKeyType<E>, pk_sa: &'a PublicKeyType<E>, vid: &'a E::ScalarField)->Self {
        let id = E::ScalarField::rand(rng);
        let sid = E::ScalarField::rand(rng);
        let pk_ra_value= pk_ra.bb_value();
        let d = E::ScalarField::rand(rng);
        let vsid = pk_ra_value.v*sid ;
        let alpha = vsid + E::G1::generator()*d; 

        let uid = pk_ra_value.u*id;
        let vvid = pk_sa.bb_value().v*id;
        
        
        UserAN{
            id,
            uid,
            vvid,
            sid,
            vsid,
            d,
            alpha,
            pk_ra,
            pk_sa,
            vid,
            signature_ra: None,
            signature_sa: None,
        }
    }
    pub fn get_vvid(&self) -> &E::G1{
        &self.vvid
    }
    fn unblind(&self, blinded_sig: &BBSignature<E>, d: &E::ScalarField) -> BBSignature<E> {
        blinded_sig.unblind(d)
    }
    
}
impl<'a, E:Pairing> UserTrait<'a,E> for UserAN<'a, E>{
    /// User registration step 1 : 
    /// Sending id, pk and proof of knowledge of sid to RA
    fn user_registration_1<CR>(&self, _crs: &CRS<E>, _rng: &mut CR) -> UserRAComm where CR:Rng {   
        let v = self.pk_ra.bb_value().v;
        let proof = SchnorrProof2::new(&self.sid, &self.d, &v, self.pk_ra.bb_value(), &self.uid,&self.alpha);

        let mut id_compressed= Vec::new();
        let mut pk_compressed= Vec::new();
        let mut proof_compressed= Vec::new();
        self.uid.serialize_compressed(&mut id_compressed).unwrap();
        self.alpha.serialize_compressed(&mut pk_compressed).unwrap();
        proof.serialize_compressed(&mut proof_compressed).unwrap();
        UserRAComm { 
            id: id_compressed, 
            pk: pk_compressed, 
            proof: proof_compressed, 
            proof_type: Proofs::SC2 }
    }

    /// User registration step 3 : 
    /// Receiving RA's signature on (id, pk) and verifying it
    fn user_registration_3(&mut self,signature: & 'a SignatureType<E>)-> Result<(), UserRegistrationError> {
        let signature_value = signature.bb_value();
        if self.pk_ra.verify(&signature,&self.uid, &self.alpha, ).is_ok() {
            let unblinded_signature = self.unblind(signature_value, &self.d);
            self.signature_ra = Some(SignatureType::BB(unblinded_signature));
            Ok(())
        } else {
            Err(UserRegistrationError::InvalidRASignature)
        }
        
    }
    fn set_signature_sa(&mut self,signature: &'a SignatureType<E>) {

        self.signature_sa = Some(signature);
        
    }
    
     /// Submission
    /// Computation of proofs of knowledge of valid signatures from RA and SA and
    /// computation of commitment to pk, token and proofs of their correctness
    fn submission<R:Rng>(&self, rng: &mut R,  _crs: &CRS<E>,_crs2:&CRS<E>,_crs_exp: &CRS<E>,_ots_scheme: &OTSignatureSchemeType) -> SubmissionType<E> {
        let token = E::pairing(E::G1::generator(), E::G2::generator())*(E::ScalarField::from(1)/(self.sid+self.vid));

        let d1 = E::ScalarField::rand(rng);
        let d2 = E::ScalarField::rand(rng);

        let g2 = E::G2::generator();

        let signature_ra= self.signature_ra.as_ref().unwrap().bb_value();
        let signature_sa = self.signature_sa.as_ref().unwrap().bb_value();
        let pk_ra = self.pk_ra.bb_value();
        let pk_sa = self.pk_sa.bb_value();
        let s1 = signature_ra.s1 +(self.uid + self.vsid+pk_ra.h )*d1;
        let s2 = signature_ra.s2 + g2*d1;
        let s3 = signature_sa.s1 + (pk_sa.u*self.vid + pk_sa.v*self.id+pk_sa.h) *d2;
        let s4 = signature_sa.s2 + g2*d2;        
        
        let mut proof =ProofAnonize::new(
            &self.id, &self.sid, &self.pk_ra.bb_value(),
            &self.pk_sa.bb_value(),
            &s1,&s2,&s3,&s4,
            &token.0,
            );
        while proof.is_err() {
            proof =ProofAnonize::new(
            &self.id, &self.sid, &self.pk_ra.bb_value(),
            &self.pk_sa.bb_value(),
            &s1,&s2,&s3,&s4,
            &token.0,
            );
        }
        let proof = proof.unwrap();

        let token = token.0;
        
        SubmissionType::AN(SubmissionAnonize{
            token,
            s2,
            s4,
            proof
        })
    }
}
