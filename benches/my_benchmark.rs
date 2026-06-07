#![allow(warnings)]
use anonymous_survey::utils::utils::CRS;
use ark_bls12_381::g2;
use ark_ec::bls12::Bls12;
use criterion::{criterion_group, criterion_main, Criterion, black_box as bb2};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize,Compress, SerializationError, Write};
use ark_ec::{ pairing::Pairing, pairing::PairingOutput as GT, 
    PrimeGroup,
    AffineRepr,
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,map_to_curve_hasher::MapToCurve}};
use anonymous_survey::{utils::curve_hasher::MapToCurveBasedHasher as MCCH};
use ark_std::{UniformRand, rand::Rng};
use ark_ff::{Zero};

use ark_std::{test_rng, hint::black_box as bb};
use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr as ScalarField, Fq, g1::Config as G1Config,g2::Config as G2Config};

use ark_ff::field_hashers::DefaultFieldHasher;
use generic_array::{GenericArray, typenum::U32};
use sha2::{ Sha256, Digest};
use anonymous_survey::{DOMAIN}; 


use groth_sahai::{AbstractCrs, CRS as CRSLib};


use anonymous_survey::utils::signature::sps_improved::*;

use anonymous_survey::utils::utils::*;

use anonymous_survey::survey_authority::*;
use anonymous_survey::registration_authority::*;
use anonymous_survey::utils::signature::pbbb::*;
use anonymous_survey::utils::gs::*;
use anonymous_survey::utils::ots::lamport_diffie::*;
use anonymous_survey::utils::ots::ots::*;
use rand::rand_core::le;

mod benches_sep;


fn anonymous_survey_gs_benchmark() {
    // Benchmarking code for AS all GS proofs, LD OTS

    let crs_type = CRStype::GS;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CrsG2::<Bls12_381>::new(&mut rng);

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();


}
fn anonymous_survey_gs_p_benchmark() {
    // Benchmarking code for AS all GS proofs, P OTS
    let crs_type = CRStype::GS;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CrsG2::<Bls12_381>::new(&mut rng);

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {});
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}
fn anonymous_survey_gslib_benchmark(){
    //AS: GSLIB, LD OTS
    let crs_type = CRStype::GSLIB;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::GSLIB(CRSLib::<Bls12_381>::generate_crs(&mut rng));
    let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}

fn anonymous_survey_gslib_p_benchmark(){
    let crs_type = CRStype::GSLIB;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::GSLIB(CRSLib::<Bls12_381>::generate_crs(&mut rng));
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}
fn anonymous_survey_schnorr_gs_benchmark() {
    // AS: Schnorr, GS, LD OTS
    let crs_type = CRStype::GS;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::<Bls12_381>::None;
    let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}

fn anonymous_survey_schnorr_gs_p_benchmark() {
    let crs_type = CRStype::GS;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::<Bls12_381>::None;
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();


}
fn anonymous_survey_schnorr_gslib_benchmark(){
    //AS: Schnorr, GSLIB, LD OTS
    let crs_type = CRStype::GSLIB;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::<Bls12_381>::None;
    let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}
fn anonymous_survey_schnorr_gslib_p_benchmark(){
    //AS: Schnorr, GSLIB, P OTS
    let crs_type = CRStype::GSLIB;
    let group1 = Group::G1;
    let group2 = Group::G2;
    let mut rng = test_rng();
    let crs_ur  = CRS::<Bls12_381>::None;
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();

}

fn anonize_benchmark() {
    //AN
  let crs_type = CRStype::AN;
    let group1 = Group::None;
    let group2 = Group::None;
    let mut rng = test_rng();
    let crs_ur  = CRS::<Bls12_381>::None;
    let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });

    let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::BB(bb(BBSignatureScheme)));
    
       
    //RA generation
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    //SA generation
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    //CRS generation
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);    

    //User
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);

    // User registration

    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let signature_ra = ra.user_registration_2(&mut rng, &user_ra_comm,&crs_ur).unwrap();
    let signature_ra =SignatureType::deserialize(&signature_ra.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();

    // Survey registration
    let signature_sa = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    // Authorised
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    // Submission
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();



}

fn e1(g1: G1, s: ScalarField) -> G1 {
    
    bb(g1*s)
}

fn e2(g2: G2, s: ScalarField) -> G2 {
    
    bb(g2*s)
}
fn pairing(g1: G1, g2: G2) -> GT<Bls12_381> {
    bb(Bls12_381::pairing(g1, g2))
}
fn mt(p1: GT<Bls12_381>, p2: GT<Bls12_381>) -> GT<Bls12_381> {
    bb(p1+p2)
}
fn hash(s: ScalarField) -> GenericArray<u8,U32> {
    let mut hasher = Sha256::new();
        hasher.update(s.to_string().as_bytes());
        hasher.update(s.to_string().as_bytes());
        hasher.update(s.to_string().as_bytes());
        hasher.update(s.to_string().as_bytes());
        hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        //hasher.update(s.to_string().as_bytes());
        hasher.update("message".as_bytes());
        hasher.finalize()
}
fn h1(vid: &G1)-> G1Affine{
    let g1_mapper = MapToCurveBasedHasher::<
            G1,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Config>,
        >::new(DOMAIN)
        .unwrap();
        g1_mapper.hash(vid.to_string().as_bytes()).unwrap()
}

fn h2(msg:&G2)-> (G2Affine,G2Affine){
    let g2_mapper = MCCH::<
            G2,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G2Config>,
        >::new(DOMAIN)
        .unwrap();
        g2_mapper.hash2(msg.to_string().as_bytes()).unwrap()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample-size-example");
    group.sample_size(50);
    //group.bench_function("Anonymous Survey GS LDOTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_gs_benchmark()); 
    //               }));
    //group.bench_function("Anonymous Survey GS POTS", |b|
    //b.iter(|| 
    //{//anonymous_survey_benchmark();  
    //   std::hint::black_box(anonymous_survey_gs_p_benchmark()); 
    //}));
    //group.bench_function("Anonymous Survey GSLib LDOTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_gslib_benchmark()); 
    //               }));
    //group.bench_function("Anonymous Survey GSLib POTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_gslib_p_benchmark()); 
    //               }));
    //group.bench_function("AS Schnorr GS LOTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_schnorr_gs_benchmark()); 
    //               }));
    //group.bench_function("AS Schnorr GS POTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_schnorr_gs_p_benchmark()); 
    //               }));
    //group.bench_function("AS Schnorr GSLIB LDOTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_schnorr_gslib_benchmark()); 
    //               }));
    //group.bench_function("AS Schnorr GSLIB POTS", |b|
    //            b.iter(|| 
    //               {//anonymous_survey_benchmark();  
    //                   std::hint::black_box(anonymous_survey_schnorr_gslib_p_benchmark()); 
    //               }));
    //group.bench_function("AN", |b| b.iter(|| {anonize_benchmark(); bb(0)}));
    let s = bb(ScalarField::from(82));
    let g1 = bb(G1::generator());
    //group.bench_function("E1", |b| b.iter(|| {bb(e1(g1, s))}));
    let g2 = bb(G2::generator());
    //group.bench_function("E2", |b| b.iter(|| {bb(e2(g2, s))}));
    let g = bb(g1*s);
    let h = bb(g2*s);
    //group.bench_function("Pairing", |b| b.iter(|| {bb(pairing(g, h))}));
    let p1 = bb(Bls12_381::pairing(g1, g2));
    let p2 = bb(Bls12_381::pairing(g, h));
    //group.bench_function("MT", |b| b.iter(|| {bb(mt(p1, p2))}));
    group.bench_function("Hash", |b| b.iter(|| {bb(hash(s))}));
    //group.bench_function("Hash to curve G1", |b| b.iter(|| {bb(h1(&g1))}));
    group.bench_function("Hash to curve G2", |b| b.iter(|| {bb(h2(&g2))}));
    //let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });  
    //let (ovk, _osk) = ots_scheme.generate_keys::<Bls12_381>();
    //let mut hasher = Sha256::new();
    //    hasher.update(s.to_string().as_bytes());
    //    
    //    match ovk {
    //        OTSPublicKeyType::LD(ovk_ld) => {
    //            for i in 0..256 {
    //                hasher.update(ovk_ld.vec[i][0]);
    //                hasher.update(ovk_ld.vec[i][1]);
    //            }
    //        },
    //        OTSPublicKeyType::P(ovk_p) =>{
    //            let mut serialized_bytes: Vec<u8> = Vec::new();
    //            ovk_p.vk_1.serialize_compressed(&mut serialized_bytes).unwrap();
    //            ovk_p.vk_2.serialize_compressed(&mut serialized_bytes).unwrap();
    //            ovk_p.hk.serialize_compressed(&mut serialized_bytes).unwrap();
    //            hasher.update(&serialized_bytes);
    //        }
    //
    //    }
    //let f = hasher.finalize();
    //group.bench_function("Hash to curve G2", |b| b.iter(|| {bb(h2(f.as_ref()))}));
}
criterion_group!(benches, criterion_benchmark);//, benches_sep::criterion_benchmark_sep);
criterion_main!(benches);