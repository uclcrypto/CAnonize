use ark_ec::{ pairing::Pairing, pairing::PairingOutput as GT, 
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve, map_to_curve_hasher::MapToCurve},
    PrimeGroup,
    AffineRepr,
     };
use ark_ff::{Zero,field_hashers::DefaultFieldHasher,Fp, MontBackend};
use ark_std::{UniformRand, test_rng, rand::Rng};
use ark_bls12_381::{
    g1::Config as G1Config,};
use ark_serialize::{CanonicalSerialize};

use groth_sahai::prover::CProof;
use groth_sahai::{CRS as CRSLib,statement::PPE, statement::MSMEG1, data_structures::Matrix, data_structures::{vec_to_col_vec,Com2}};
use groth_sahai::verifier::Verifiable;

use sha2::{ Sha256, };
use ark_std::{borrow::Borrow};
use ark_bls12_381::fr::FrConfig;


use crate::{DOMAIN, utils::{errors::SubmissionError, gs::*, utils::Proofs}};
use crate::utils::utils::{PublicKey,PublicKeyType, SigningKeyType, SignatureScheme,SignatureSchemeType, SignatureType, SignatureTypeCompressed, Commit1WithRandomness, SubmissionType, Submission, SubmissionAnonize,CRS, CProofCanonical};


pub struct SA<'a, E:Pairing>{ //TODO check if reference needed
    pk: PublicKeyType<E>,
    sk: SigningKeyType<E>,
    vid: E::ScalarField,
    pub gvid : E::G1,
    pk_ra:  &'a PublicKeyType<E>,

}
impl<'a, E:Pairing> SA<'a, E>{
    pub fn new(pk_ra: &'a PublicKeyType<E>,signature_scheme: &SignatureSchemeType)->Self {
        let mut rng = test_rng(); 
        
        let vid = E::ScalarField::rand(&mut rng);

        let (gvid, pk, sk) = match signature_scheme {
            SignatureSchemeType::SPSImp(scheme) => {
                let (pk, sk) = scheme.generate_keys(&E::ScalarField::zero());
                (E::G1::generator()*vid, pk, sk)
            },
            SignatureSchemeType::BB(scheme) => {
                let (pk,sk) = scheme.generate_keys(&E::ScalarField::rand(&mut rng));
                (pk_ra.bb_value().u*vid, pk, sk)
            },
        };
        
        SA{
            pk,
            sk,
            vid,
            gvid,
            pk_ra,
        }
    }
    pub fn get_pk(&self) -> &PublicKeyType<E> {
        &self.pk
    }
    pub fn get_vid(&self) -> &E::ScalarField {
        &self.vid
    }
    pub fn survey_registration<R: Rng>(&self, rng: &mut R, id: &E::G1) -> SignatureTypeCompressed {

        let signature = SigningKeyType::signature(&self.sk, rng,id,&self.gvid); 

        match signature {
            SignatureType::SPSImp(sig) => {
                let mut sig_bytes = Vec::new();
                sig.serialize_compressed(&mut sig_bytes).unwrap();
                SignatureTypeCompressed{signature: sig_bytes}
            },
            SignatureType::BB(sig) => {
                let mut sig_bytes = Vec::new();
                sig.serialize_compressed(&mut sig_bytes).unwrap();
                SignatureTypeCompressed{signature: sig_bytes}
            },
        }
    }
    // Submission proof verification using GS from library
    fn verify_ra1(&self, proof: &CProof<E>, crs: &CRSLib<E>) -> bool {
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

        let equ: PPE<E> = PPE::<E> {//TODO modify
            a_consts,
            b_consts,
            gamma,
            target,
        };
        equ.verify(proof, crs)
    }
    // Submission proof verification using GS from library
    fn verify_ra2(&self, proof: &CProof<E>, crs: &CRSLib<E>) -> bool {

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
        equ.verify(proof, crs)
    }
    /// Submission proof verification using GS from library
    fn verify_sa1(&self, proof: &CProof<E>, crs: &CRSLib<E>) -> bool {
        let a_consts: Vec<E::G1Affine> = vec![E::G1Affine::zero()];
        let pk = self.pk.sps_imp_value();
        let b_consts: Vec<E::G2Affine> = vec![
            E::G2Affine::from(pk.hk1a),
            E::G2Affine::from(pk.hk3a),
            E::G2Affine::from(pk.hk4a),
            E::G2Affine::from(pk.hk5a),
            E::G2Affine::from(pk.hk6a),
            E::G2Affine::from(pk.ha),
        ];
        let gamma: Matrix<E::ScalarField> = vec![ vec![E::ScalarField::zero()], 
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()],
                                                  vec![E::ScalarField::zero()]];
        let pk_ra = self.pk_ra.sps_imp_value();
        let target: GT<E> = E::pairing(-E::G1::generator(), pk_ra.hka)+E::pairing(-self.gvid,E::G2Affine::from(pk_ra.hk2a)); 

        let equ: PPE<E> = PPE::<E> {
            a_consts,
            b_consts,
            gamma,
            target,
        };
        equ.verify(proof,crs)
    }
    /// Submission proof verification using GS from library
    fn verify_sa2(&self, proof: &CProof<E>, crs: &CRSLib<E>) -> bool {

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
        equ.verify(proof,crs)
    }
    //Submission proof verification using GS from library
    fn verify_token11(&self, proof: &CProof<E>, crs1: &CRSLib<E>, crs2: &CRSLib<E>, pk_commitment: &Commit1WithRandomness<E>) -> bool {

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
        equ.verify(proof,crs2)
    }
    /// Submission proof verification using GS from library
    fn verify_token12(&self, proof: &CProof<E>, crs1: &CRSLib<E>, crs2: &CRSLib<E>, pk_commitment: &Commit1WithRandomness<E>) -> bool {

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
        equ.verify(proof,crs2)
    }
    /// Submission proof verification using GS from library
    fn verify_token2(&self, proof: &CProof<E>, crs: &CRSLib<E>, hash: &E::G1, token: &E::G1) -> bool {

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
        equ.verify(proof,crs)
    }

    fn verify_as_gs(&self,submission: &Submission<E>, crs: &CrsG1<E>, crs2: &CrsG2<E>, crs_exp2: &CrsG2<E>) -> Result<(), SubmissionError> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>,
    <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2> {   
        let (proof_ra1,proof_ra2,proof_sa1,proof_sa2,proof_token) = submission.proof.gs_value();

        //OTS verification
        let hash3=Submission::<E>::hash3(&self.vid, &submission.token, &submission.pk_commitment.gs_value(), &proof_ra1, &proof_ra2, &proof_sa1, &proof_sa2, &proof_token);
        submission.ovk.overify(&submission.ots, &hash3).map_err(|_| SubmissionError::InvalidOTS)?;
        
        //CRS
        let hash2 = Submission::<E>::hash2(&self.vid, &submission.ovk);
        let crs_exp:CrsG2<E>=CrsG2 { g11: hash2.0.into(), g12: hash2.1.into(), g21: crs_exp2.g21, g22: crs_exp2.g22 };
        //GS proofs verification using our implementation
        let hash = Submission::<E>::hash1(&self.vid);
        if !proof_ra1.verify(&crs, self.pk_ra.sps_imp_value()) || !proof_ra2.verify(&crs2, &crs, &proof_ra1.commitments[2], &proof_ra1.commitments[4]){
            return Err(SubmissionError::InvalidRAProof);
        }
        if !proof_sa1.verify(&crs, self.pk.sps_imp_value(), &proof_ra1.commitments[0], &self.gvid)
            || ! proof_sa2.verify(&crs2, &crs, &proof_sa1.commitments[0], &proof_sa1.commitments[2]){
            return Err(SubmissionError::InvalidSAProof);
            }
        if !  proof_token.verify(&crs, &crs_exp, &hash.into(), &submission.token, &submission.pk_commitment.gs_value()){
            return Err(SubmissionError::InvalidTokenProof);
        }
        Ok(())
    }
    fn verify_as(&self, submission: &Submission<E>, crs: &CRSLib<E>, crs2: &CRSLib<E>) -> Result<(), SubmissionError> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>,
    <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2>{
        let (proof_ra1,proof_ra2,proof_sa1,proof_sa2,proof_token11, proof_token12, proof_token2) = submission.proof.gslib_value();

        //OTS verification
        let hash3=Submission::<E>::hash3_gslib(&self.vid, &submission.token, &submission.pk_commitment.gslib_value(), &CProofCanonical(proof_ra1.clone()), &CProofCanonical(proof_ra2.clone()), &CProofCanonical(proof_sa1.clone()), &CProofCanonical(proof_sa2.clone()), &CProofCanonical(proof_token11.clone()), &CProofCanonical(proof_token12.clone()), &CProofCanonical(proof_token2.clone()));
        submission.ovk.overify(&submission.ots, &hash3).map_err(|_| SubmissionError::InvalidOTS)?;

        //CRS
        let hash2=Submission::<E>::hash2(&self.vid, &submission.ovk);
        let crs2_new = CRSLib::<E>{
            u: crs2.u.clone(),
            v: vec![Com2::<E>(hash2.0.into(), hash2.1.into()), crs2.v[1]],
            g1_gen: crs2.g1_gen,
            g2_gen: crs2.g2_gen,
            gt_gen: crs2.gt_gen,
        };

        // hash for token verification
        let g1_mapper = MapToCurveBasedHasher::<
            E::G1,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Config>,
        >::new(DOMAIN)
        .unwrap();
        let hash = g1_mapper.hash(self.vid.to_string().as_bytes()).unwrap();
        //pk commitment
        let pk_commitment = &submission.pk_commitment.gslib_value();

        //GS proofs verification using GS from library
        if !self.verify_ra1(proof_ra1, crs) || !self.verify_ra2(proof_ra2, crs){
            Err(SubmissionError::InvalidRAProof)
        }
        else if !self.verify_sa1(proof_sa1, crs) || !self.verify_sa2(proof_sa2, crs) {
            Err(SubmissionError::InvalidSAProof)
        }
        else if !self.verify_token11(proof_token11, crs,&crs2_new, pk_commitment){
            Err(SubmissionError::InvalidTokenProof)
        } 
        else if !self.verify_token12(proof_token12, crs, &crs2_new, pk_commitment) {
            Err(SubmissionError::InvalidTokenProof)
        }
        else if !self.verify_token2(proof_token2, &crs2_new, &hash.into(), &submission.token) {
            Err(SubmissionError::InvalidTokenProof)
        } 
        else {
            Ok(())
        }
    }
    fn verify_an(&self, submission: &SubmissionAnonize<E>) -> Result<(), SubmissionError> {
        let proof = &submission.proof;
        let s2 = &submission.s2;
        let s4 = &submission.s4;
        let pk_ra = self.pk_ra.bb_value();
        let pk_sa = self.pk.bb_value();
        let vid = &self.vid;
        let token = &submission.token;
        if !proof.verify(s2, s4, pk_ra, pk_sa, vid, token) {
            Err(SubmissionError::InvalidSAProof)
        } else {
            Ok(())
        }
    }

    pub fn submission_check(&self, submission: &SubmissionType<E>, crs: &CRS<E>, crs2: &CRS<E>, crs_exp2: &CRS<E>,) -> Result<(), SubmissionError> where <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g1::Config>: MapToCurve<<E as Pairing>::G1>,
    <E as Pairing>::ScalarField: Borrow<Fp<MontBackend<FrConfig, 4>, 4>>, WBMap<ark_bls12_381::g2::Config>: MapToCurve<<E as Pairing>::G2>{

        let _hash=E::G1::zero(); //TODO check hash
    
        match submission {
            SubmissionType::AS(subm) => {
                match crs {
                    CRS::GSLIB(_) => {
                        let s = subm.deserialize(&Proofs::GSLIB);
                        self.verify_as(&s, crs.gslib_value(), crs2.gslib_value())
                    },
                    CRS::GS1(_) => {
                        let s = subm.deserialize(&Proofs::GS);
                        self.verify_as_gs(&s, crs.gs1_value(), crs2.gs2_value(), crs_exp2.gs2_value())
                    },
                    _ => panic!("Invalid CRS type GS1 for GS verification"),
                }

                },
            SubmissionType::AN(subm) => 
            {
                let s = subm;
                self.verify_an(&s)

            }, 
            SubmissionType::None => panic!("No submission provided"),
        }
    }
}

pub fn authorized<E: Pairing>(pk_sa: &PublicKeyType<E>, id: &E::G1, vid: &E::G1, signature: &SignatureType<E>) -> bool {
    let result= match pk_sa {
        PublicKeyType::SPSImp(pk) => pk.verify(signature, id,vid),
        PublicKeyType::BB(pk) => pk.verify(signature, id, vid),
    };
    if result.is_ok() {
        true
    } else {
        false
    }
}