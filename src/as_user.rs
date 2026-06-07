
use ark_ec::{ pairing::Pairing, pairing::PairingOutput as GT,
    PrimeGroup,
    hashing::{curve_maps::wb::WBMap,map_to_curve_hasher::MapToCurve}, 
    AffineRepr};
use ark_std::{UniformRand, rand::Rng};
use ark_ff::{Zero, Fp, MontBackend};
use ark_serialize::{CanonicalSerialize,};

use ark_std::{borrow::Borrow};
use ark_bls12_381::fr::FrConfig;

use crate::{utils::errors::*};
use crate::utils::utils::{PublicKeyType, SignatureType, UserTrait, UserRAComm, OTSignatureSchemeType, ProofTypeCompressed,Proofs, SchnorrProof,CRS, SubmissionType, Submission, SubmissionCompressed,SubmissionProof, CProofCanonical, Commit1WithRandomness, commit_g1_with_randomness, OTS,};



use groth_sahai::data_structures::{Matrix, vec_to_col_vec,Com2};
use groth_sahai::prover::{CProof,Provable};
use groth_sahai::statement::*;
use groth_sahai::{CRS as CRSLib};
use crate::utils::gs::{CrsG1, CrsG2, GSU, CommitmentG1, GSRA11, GSRA12, GSSA11, GSSA3};


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
pub struct UserAS<'a,E:Pairing>{
    id: E::ScalarField,
    gid: E::G1,
    sid: E::ScalarField,
    pk: E::G1,
    pk_ra: &'a PublicKeyType<E>,
    pk_sa: &'a PublicKeyType<E>, //TODO make it a dictionary
    vid: &'a E::ScalarField,
    gvid: E::G1,
    signature_ra: Option<&'a SignatureType<E>>,
    signature_sa: Option<&'a SignatureType<E>>,
}
impl<'a, E:Pairing> UserAS<'a, E>{
    pub fn new<R:Rng>(rng: &mut R, pk_ra: &'a PublicKeyType<E>, pk_sa: &'a PublicKeyType<E>, vid: &'a E::ScalarField)->Self {
        let id = E::ScalarField::rand(rng);
        let gid = E::G1::generator()*id; 
        let sid = E::ScalarField::rand(rng);
        let pk = E::G1::generator()*sid; 
        let gvid = E::G1::generator()*vid; 
        UserAS{
            id,
            gid,
            sid,
            pk,
            pk_ra,
            pk_sa,
            vid,
            gvid,
            signature_ra: None,
            signature_sa: None,
        }
    }

    pub fn get_gid(&self) -> &E::G1{
        &self.gid
    }
    

    // GS proof using library
    fn generate_proof_pk<CR>(&self, crs: &CRSLib<E>, rng: &mut CR, ) -> CProof<E> where CR:Rng{
        
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::zero()
        ];
        let scalar_yvars: Vec<E::ScalarField> = vec![self.sid];
        let a_consts: Vec<E::G1Affine> = vec![E::G1::generator().into()];
        let b_consts: Vec<E::ScalarField> = vec![E::ScalarField::zero()];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero()]];
        let target: E::G1Affine = E::G1Affine::from(self.pk);
        let equ: MSMEG1<E> = MSMEG1::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &scalar_yvars, &crs, rng);
        
        proof
    }
    //GS proof using our own implementation
    fn generate_proof_pk_gs(&self, crs: &CrsG2<E> ) -> GSU<E>{
        
        GSU::<E>::new(crs, &self.sid)
               
    }   
    fn ur1_gslib<CR>(&self,  crs: &CRSLib<E>, rng: &mut CR) -> UserRAComm where CR:Rng {  
        // GS proof using library
        let proof = self.generate_proof_pk(crs, rng);
        let mut id_compressed= Vec::new();
        let mut pk_compressed= Vec::new();
        let mut proof_compressed= Vec::new();
        self.gid.serialize_compressed(&mut id_compressed).unwrap();
        self.pk.serialize_compressed(&mut pk_compressed).unwrap();
        CProofCanonical(proof).serialize_compressed(&mut proof_compressed).unwrap();
        UserRAComm {
            id: id_compressed,
            pk: pk_compressed,
            proof: proof_compressed,
            proof_type: Proofs::GSProof,
        }
    }
    fn ur1_gs(&self,  crs: &CrsG2<E>) -> UserRAComm {  
        //GS proof using our own implementation
        let proof = self.generate_proof_pk_gs(crs);
        let mut id_compressed= Vec::new();
        let mut pk_compressed= Vec::new();
        let mut proof_compressed= Vec::new();
        self.gid.serialize_compressed(&mut id_compressed).unwrap();
        self.pk.serialize_compressed(&mut pk_compressed).unwrap();
        proof.serialize_compressed(&mut proof_compressed).unwrap();
        UserRAComm {
            id: id_compressed,
            pk: pk_compressed,
            proof: proof_compressed,
            proof_type: Proofs::GSRA,
        }
    }
    fn ur1_sc(&self, _crs: &CRS<E>) -> UserRAComm {   
        // Schnorr proof
        let proof = SchnorrProof::new(&self.sid, 
                                        &self.pk_ra.sps_imp_value(), 
                                        &self.gid, 
                                        &self.pk   );
        let mut id_compressed= Vec::new();
        let mut pk_compressed= Vec::new();
        let mut proof_compressed= Vec::new();
        self.gid.serialize_compressed(&mut id_compressed).unwrap();
        self.pk.serialize_compressed(&mut pk_compressed).unwrap();
        proof.serialize_compressed(&mut proof_compressed).unwrap();
        UserRAComm {
            id: id_compressed,
            pk: pk_compressed,
            proof: proof_compressed,
            proof_type: Proofs::SC,
        }
    }

    fn subm_gs<R:Rng>(&self, rng: &mut R, crs: &CrsG1<E>,crs2:&CrsG2<E>, crs_exp2: &CrsG2<E>, r1: &E::ScalarField, r2: &E::ScalarField, hash: &E::G1) ->(GSRA11<E>,GSRA12<E>,GSSA11<E>,GSRA12<E>,GSSA3<E>) {
        // submission proof using our own GS implementation
        let signature_ra =self.signature_ra.as_ref().unwrap().sps_imp_value();
        let signature_sa =self.signature_sa.as_ref().unwrap().sps_imp_value();
        let (proof_ra1, r_gid,r_rho, r_psi) = GSRA11::<E>::new(rng, &crs,self.pk_ra.sps_imp_value(),signature_ra,&self.gid, &self.pk);
        let proof_ra2 = GSRA12::<E>::new(&crs, &crs2, signature_ra, &r_rho,  &r_psi);
        let (proof_sa1, r_rho2, r_psi2) = GSSA11::<E>::new(rng, &crs,self.pk_sa.sps_imp_value(), signature_sa,&r_gid);
        let proof_sa2 = GSRA12::<E>::new(&crs, &crs2, signature_sa, &r_rho2,  &r_psi2);
        let proof_exp = GSSA3::<E>::new(&crs, &crs_exp2, &self.sid, &r1, &r2, hash.into());
        (proof_ra1,proof_ra2,proof_sa1,proof_sa2,proof_exp)
    }
    fn subm_gslib<R:Rng>(&self, rng: &mut R, crs: &CRSLib<E>,crs2:&CRSLib<E>, hash: &E::G1, pk_commitment: &Commit1WithRandomness<E>, token: &E::G1) -> (CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>,CProof<E>){ 
        // submission proof using GS from library

        //TODO add token and pk_commitment to user struct ?
        let proof_ra1 = self.generate_proof_ra1(crs, rng);
        let proof_ra2 = self.generate_proof_ra2(crs, rng);
        let proof_sa1 = self.generate_proof_sa1(crs, rng);
        let proof_sa2 = self.generate_proof_sa2(crs, rng);
        let proof_token11 = self.generate_proof_token11(crs, crs2, rng, &pk_commitment,  &pk_commitment.rand);
        let proof_token12 = self.generate_proof_token12(crs, crs2, rng, &pk_commitment,  &pk_commitment.rand);
        let proof_token2 = self.generate_proof_token2(crs2, rng, &hash, &token, &pk_commitment.rand);
        (proof_ra1,proof_ra2, proof_sa1,proof_sa2,proof_token11,proof_token12,proof_token2)
    }

    
}
    

impl<'a, E:Pairing> UserTrait<'a,E> for UserAS<'a, E>{
    /// User registration step 1 : 
    /// Sending id, pk and proof of knowledge of sid to RA
    fn user_registration_1<CR>(&self, crs: &CRS<E>, rng: &mut CR) -> UserRAComm where CR:Rng{   
        match crs {
            CRS::None => self.ur1_sc(crs),
            CRS::GSLIB(c) => self.ur1_gslib(c, rng),
            CRS::GS2(c) => self.ur1_gs(c),
            _ => panic!("Wrong CRS type"),
        }
        
    }
    /// User registration step 3 : 
    /// Receiving RA's signature on (id, pk) and verifying it
    fn user_registration_3(&mut self,signature: &'a SignatureType<E>)-> Result<(), UserRegistrationError> {
        let id  =  E::G1::generator()*self.id; 
        if self.pk_ra.verify(signature,&id, &self.pk, ).is_ok() {
            self.signature_ra = Some(signature);
            Ok(())
        } else {
            Err(UserRegistrationError::InvalidRASignature)
        }
        
    }
    fn set_signature_sa(&mut self,signature: &'a SignatureType<E>) {

        self.signature_sa = Some(signature);
        
    }
    fn submission<R:Rng>(&self, rng: &mut R, crs: &CRS<E>,crs2:&CRS<E>, crs_exp2: &CRS<E>, ots_scheme: &OTSignatureSchemeType) -> SubmissionType<E> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>,
    <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2>{

        //token
        let hash = Submission::<E>::hash1( &self.vid);
        let token = hash * self.sid;         
        
        //OTS keys
        let (ovk, osk) = ots_scheme.generate_keys::<E>();

        let ots_type = match ots_scheme {
            OTSignatureSchemeType::LD(_) => OTS::LD,
            OTSignatureSchemeType::P(_) => OTS::P,
        };

        match crs {
            CRS::GSLIB(_) => { //GS from library
                let crs= crs.gslib_value();
                let crs2= crs2.gslib_value();
                let pk_commitment = commit_g1_with_randomness(&E::G1Affine::from(self.pk), crs, rng); // TODO check why need to pass rng
                //CRS
                let hash2=Submission::<E>::hash2(&self.vid, &ovk);
                let crs2 = CRSLib::<E>{
                    u: crs2.u.clone(),
                    v: vec![Com2::<E>(hash2.0.into(), hash2.1.into()), crs2.v[1]],
                    g1_gen: crs2.g1_gen,
                    g2_gen: crs2.g2_gen,
                    gt_gen: crs2.gt_gen,
                };
                //Proof
                let (proof_ra1, proof_ra2, proof_sa1, proof_sa2, proof_token11, proof_token12, proof_token2) = self.subm_gslib(rng, crs,&crs2, &hash.into(), &pk_commitment, &token);
                //OTS
                let hash3 = Submission::<E>::hash3_gslib(&self.vid, &token, &pk_commitment, &CProofCanonical(proof_ra1.clone()), &CProofCanonical(proof_ra2.clone()), &CProofCanonical(proof_sa1.clone()), &CProofCanonical(proof_sa2.clone()), &CProofCanonical(proof_token11.clone()), &CProofCanonical(proof_token12.clone()), &CProofCanonical(proof_token2.clone()));
                let ots = osk.osign(&hash3);

                let serialized_pk_commitment = {
                    let mut v = Vec::new();
                    pk_commitment.serialize_compressed(&mut v).unwrap();
                    v
                };
                let serialized_token = {
                    let mut v = Vec::new();
                    token.serialize_compressed(&mut v).unwrap();
                    v
                };
                let sp = SubmissionProof::GSLIB(proof_ra1,proof_ra2, proof_sa1, proof_sa2, proof_token11, proof_token12, proof_token2);
                SubmissionType::AS(SubmissionCompressed {
                    pk_commitment: serialized_pk_commitment,
                    token: serialized_token,
                    proof: ProofTypeCompressed::GSLIB(sp.serialize()),
                    ovk: ovk.serialize(),
                    ots: ots.serialize(),
                    ots_type: ots_type,
                })
            }, 
            CRS::GS1(c)=> { // GS implemented
                //Commitment
                let (pk_commitment, [r1,r2]) = CommitmentG1::commit(rng, &c, &self.pk);
                //CRS
                let hash2=Submission::<E>::hash2(&self.vid, &ovk);
                let crs_exp:CrsG2<E>=CrsG2 { g11: hash2.0.into(), g12: hash2.1.into(), g21: crs_exp2.gs2_value().g21, g22: crs_exp2.gs2_value().g22 };
                //Proof
                let (proof_ra1,proof_ra2, proof_sa1,proof_sa2,proof_exp)=self.subm_gs(rng, c,crs2.gs2_value(), &crs_exp,&r1,&r2,&hash.into());
                //ots
                let hash3 = Submission::<E>::hash3(&self.vid, &token, &pk_commitment, &proof_ra1, &proof_ra2, &proof_sa1, &proof_sa2, &proof_exp);
                let ots = osk.osign(&hash3);

                let serialized_pk_commitment = {
                    let mut v = Vec::new();
                    pk_commitment.serialize_compressed(&mut v).unwrap();
                    v
                };
                let serialized_token = {
                    let mut v = Vec::new();
                    token.serialize_compressed(&mut v).unwrap();
                    v
                };
                let sp = SubmissionProof::GS(proof_ra1,proof_ra2, proof_sa1, proof_sa2, proof_exp);
                SubmissionType::AS(SubmissionCompressed {
                    pk_commitment: serialized_pk_commitment,
                    token: serialized_token,
                    proof: ProofTypeCompressed::GS(sp.serialize()),
                    ovk: ovk.serialize(),
                    ots: ots.serialize(),
                    ots_type: ots_type,
                })


            }, // GS proof
            _=> panic!("Invalid CRS type for AS submission"),
        }
        
    }
}
impl<'a, E:Pairing> UserAS<'a, E> {
    ///Submission
    /// Proof of knowledge of valid signature from RA (first part) using GS from library
    fn generate_proof_ra1<CR>(&self, crs: &CRSLib<E>, rng: &mut CR) -> CProof<E> where CR:Rng{
        let signature_ra =self.signature_ra.as_ref().unwrap().sps_imp_value();
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::from(self.gid),
            E::G1Affine::from(self.pk),
            E::G1Affine::from(signature_ra.rho),
            E::G1Affine::from(signature_ra.rho_hat),
            E::G1Affine::from(signature_ra.psi),
            E::G1Affine::from(signature_ra.gamma),
            E::G1Affine::from(-signature_ra.pi), 
        ];
        let yvars: Vec<E::G2Affine> = vec![E::G2Affine::from(signature_ra.tau)];

        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero()];
        let pk_ra = self.pk_ra.sps_imp_value();
        let b_consts: Vec<E::G2Affine> = vec![
            E::G2Affine::from(pk_ra.hk1a),
            E::G2Affine::from(pk_ra.hk2a),
            E::G2Affine::from(pk_ra.hk3a),
            E::G2Affine::from(pk_ra.hk4a),
            E::G2Affine::from(pk_ra.hk5a),
            E::G2Affine::from(pk_ra.hk6a),
            E::G2Affine::from(pk_ra.ha),
        ];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()]];
        let target: GT<E> = E::pairing(-E::G1::generator(), pk_ra.hka);

        let equ: PPE<E> = PPE::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &yvars, &crs,  rng);
        
        proof
    }
    /// Submission
    /// Proof of knowledge of valid signature from RA (second part) using GS from library
    fn generate_proof_ra2<CR>(&self, crs: &CRSLib<E>, rng: &mut CR) -> CProof<E> where CR:Rng{
        let signature_ra = self.signature_ra.as_ref().unwrap().sps_imp_value();
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::from(self.gid),
            E::G1Affine::from(self.pk),
            E::G1Affine::from(signature_ra.rho),
            E::G1Affine::from(signature_ra.rho_hat),
            E::G1Affine::from(signature_ra.psi),
            E::G1Affine::from(signature_ra.gamma),
            E::G1Affine::from(-signature_ra.pi), 
        ];
        let yvars: Vec<E::G2Affine> = vec![E::G2Affine::from(signature_ra.tau)];

        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero()];
        let b_consts: Vec<E::G2Affine> = vec![
            E::G2Affine::zero(),
            E::G2Affine::zero(),
            E::G2Affine::zero(),
            E::G2Affine::zero(),
            E::G2Affine::generator(),
            E::G2Affine::zero(),
            E::G2Affine::zero(),
        ];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()], 
                                                 vec![E::ScalarField::from(-1),],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()],
                                                 vec![E::ScalarField::zero()]];
        let target: GT<E> = GT::zero();

        let equ: PPE<E> = PPE::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &yvars, &crs,  rng);
        
        proof
    }
    ///Submission
    /// Proof of knowledge of valid signature from SA (first part) using GS from library
    fn generate_proof_sa1<CR>(&self, crs: &CRSLib<E>, rng: &mut CR) -> CProof<E> where CR:Rng{
        let signature_sa = self.signature_sa.as_ref().unwrap().sps_imp_value();
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::from(self.gid),
            E::G1Affine::from(signature_sa.rho),
            E::G1Affine::from(signature_sa.rho_hat),
            E::G1Affine::from(signature_sa.psi),
            E::G1Affine::from(signature_sa.gamma),
            E::G1Affine::from(-signature_sa.pi), 
        ];
        let yvars: Vec<E::G2Affine> = vec![E::G2Affine::from(signature_sa.tau)];

        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero()];
        let pk_sa = self.pk_sa.sps_imp_value();
        let b_consts: Vec<E::G2Affine> = vec![
            E::G2Affine::from(pk_sa.hk1a),
            E::G2Affine::from(pk_sa.hk3a),
            E::G2Affine::from(pk_sa.hk4a),
            E::G2Affine::from(pk_sa.hk5a),
            E::G2Affine::from(pk_sa.hk6a),
            E::G2Affine::from(pk_sa.ha),
        ];
        let gamma: Matrix<E::ScalarField> = vec![ vec![E::ScalarField::zero()], 
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()]];
        let target: GT<E> = E::pairing(-E::G1::generator(), pk_sa.hka)+E::pairing(-self.gvid,E::G2Affine::from(pk_sa.hk2a)); 

        let equ: PPE<E> = PPE::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &yvars, &crs,  rng);
        
        proof
    }
    /// Submission
    /// Proof of knowledge of valid signature from SA (second part) using GS from library
    fn generate_proof_sa2<CR>(&self, crs: &CRSLib<E>, rng: &mut CR) -> CProof<E> where CR:Rng{
        let signature_sa = self.signature_sa.as_ref().unwrap().sps_imp_value();
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::from(self.gid),
            E::G1Affine::from(signature_sa.rho),
            E::G1Affine::from(signature_sa.rho_hat),
            E::G1Affine::from(signature_sa.psi),
            E::G1Affine::from(signature_sa.gamma),
            E::G1Affine::from(-signature_sa.pi), 
        ];
        let yvars: Vec<E::G2Affine> = vec![E::G2Affine::from(signature_sa.tau)];

        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero()];
        let b_consts: Vec<E::G2Affine> = vec![
            E::G2Affine::zero(),
            E::G2Affine::zero(),
            E::G2Affine::zero(),
            E::G2Affine::generator(),
            E::G2Affine::zero(),
            E::G2Affine::zero(),
        ];
        let gamma: Matrix<E::ScalarField> = vec![ vec![E::ScalarField::zero()], 
                                                  vec![E::ScalarField::from(-1)],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()]];
        let target: GT<E> = GT::zero();

        let equ: PPE<E> = PPE::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &yvars, &crs,  rng);
        
        proof
    }

    /// Submission
    /// Proof of correctness of commitment to pk (part 1) using GS from library
    fn generate_proof_token11<CR>(&self,crs1:&CRSLib<E>, crs2: &CRSLib<E>, rng: &mut CR, pk_commitment:&Commit1WithRandomness<E>,rand: &Vec<Vec<<E as Pairing>::ScalarField>>) -> CProof<E> where CR:Rng{
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::zero()
        ];
        let scalar_yvars: Vec<E::ScalarField> = vec![self.sid, rand[0][0], rand[0][1]];
        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero(),vec_to_col_vec(&crs1.u)[0][0].0,vec_to_col_vec(&crs1.u)[1][0].0];
        let b_consts: Vec<E::ScalarField> = vec![E::ScalarField::zero()];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero(),E::ScalarField::zero(),E::ScalarField::zero()]];
        let target: E::G1Affine = pk_commitment.coms[0].0;
        let equ: MSMEG1<E> = MSMEG1::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };
        let proof: CProof<E> = equ.commit_and_prove(&xvars, &scalar_yvars, &crs2, rng);
        
        proof
    }
    /// Submission
    /// Proof of correctness of commitment to pk (part 2) using GS from library
    fn generate_proof_token12<CR>(&self, crs1: &CRSLib<E>, crs2: &CRSLib<E>, rng: &mut CR, pk_commitment:&Commit1WithRandomness<E>,rand: &Vec<Vec<<E as Pairing>::ScalarField>>) -> CProof<E> where CR:Rng{
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::zero()
        ];
        let scalar_yvars: Vec<E::ScalarField> = vec![self.sid, rand[0][0], rand[0][1]];
        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::generator(),vec_to_col_vec(&crs1.u)[0][0].1,vec_to_col_vec(&crs1.u)[1][0].1];
        let b_consts: Vec<E::ScalarField> = vec![E::ScalarField::zero()];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero(),E::ScalarField::zero(),E::ScalarField::zero()]];
        let target: E::G1Affine = pk_commitment.coms[0].1;
        let equ: MSMEG1<E> = MSMEG1::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };
        let proof: CProof<E> = equ.commit_and_prove(&xvars, &scalar_yvars, &crs2, rng);
        
        proof
    }
    /// Submission
    /// Proof of correctness of token using GS from library
    fn generate_proof_token2<CR>(&self, crs: &CRSLib<E>, rng: &mut CR, hash : &E::G1, token: &E::G1, rand: &Vec<Vec<<E as Pairing>::ScalarField>>) -> CProof<E> where CR:Rng{
        let xvars: Vec<E::G1Affine> = vec![
            E::G1Affine::zero()
        ];
        let scalar_yvars: Vec<E::ScalarField> = vec![self.sid, rand[0][0], rand[0][1]]; 
        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::from(*hash),E::G1Affine::zero(),E::G1Affine::zero()];
        let b_consts: Vec<E::ScalarField> = vec![E::ScalarField::zero()];
        let gamma: Matrix<E::ScalarField> = vec![vec![E::ScalarField::zero(),E::ScalarField::zero(),E::ScalarField::zero()]];
        let target: E::G1Affine = E::G1Affine::from(*token);
        let equ: MSMEG1<E> = MSMEG1::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };

        let proof: CProof<E> = equ.commit_and_prove(&xvars, &scalar_yvars, &crs, rng);
        
        proof
    }
   
}
