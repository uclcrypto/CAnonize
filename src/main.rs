#![allow(warnings)]
use ark_ec::{AffineRepr, PrimeGroup, pairing::Pairing, pairing::PairingOutput,
hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,map_to_curve_hasher::MapToCurve}, };
use ark_ff::{BigInt, Field, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{UniformRand, test_rng, rand::Rng};

use rand::rand_core::le;
use rand::{rng, thread_rng};


use ark_bls12_381::{Bls12_381, G1Projective as G1, G2Projective as G2, G1Affine, G2Affine, Fr as ScalarField, Fq, g1::Config as G1Config};
use ark_ff::field_hashers::DefaultFieldHasher;
use sha2::{ Sha256};



use groth_sahai::{AbstractCrs, B, CRS as CRSLib};

use anonymous_survey::{DOMAIN, utils::{signature, utils::{SignatureType, SignatureTypeCompressed}}}; 
use anonymous_survey::utils::utils::{setup,CRS,generate_crs,CRStype, Group, SignatureSchemeType,OTSignatureSchemeType, User, UserTrait};
use anonymous_survey::survey_authority::{SA,authorized};
use anonymous_survey::registration_authority::{RA};
use anonymous_survey::as_user::{UserAS};
use anonymous_survey::an_user::{UserAN};
use anonymous_survey::utils::signature::pbbb::{BBSignatureScheme, BBSignature};
use anonymous_survey::utils::signature::sps_improved::{SPSImpSignatureScheme, SPSImpSignature};
use anonymous_survey::utils::ots::lamport_diffie::{LDOTSignatureScheme};
use anonymous_survey::utils::ots::ots::{POTSignatureScheme};
use anonymous_survey::utils::gs::CrsG2;

use std::time::Instant;
use std::{env, vec};

fn vec_size<T>(v: &Vec<T>) -> usize {
    size_of_val(v) + v.capacity() * size_of_val(&v[0])
    //v.capacity() * size_of_val(&v[0])
}
fn vec_vec_size<T>(v: &Vec<Vec<T>>) -> usize {
    // size_of_val(v) + v.capacity() * size_of_val(&v[0])
    let mut s = size_of_val(v);
    //let mut s = 0;
    for i in 0..v.capacity() {
        s=s + vec_size(&v[i]);
    }
    s
}


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <scheme: AS/AN> <exp_type:string>", args[0]);
        std::process::exit(1);
    }
    let scheme = &args[1]; //AS for anonymous survey or AN for anonize
    let mut exp_type = "ours";     //&args[1]; //&args[2] for benchmarks;
    if (scheme == "AN"){
        exp_type = "orig.";}
    let print_time = env::args() //for only printing execution times
        .nth(2)
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true);
    let print_size = env::args() //for only printing sizes
        .nth(3)
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true);
    let print_header = env::args() //for only printing header
        .nth(4)
        .and_then(|s| s.parse::<bool>().ok())
        .unwrap_or(true);

    let mut rng = test_rng();
    let signature_scheme_type:SignatureSchemeType; //SPSImp for AS, BB for AN
    let mut crs_ur : CRS<Bls12_381>;
    let crs_type:CRStype;
    let group1:Group;
    let group2:Group;
    
    let mut schnorr= false;
    let ur_proof_type = "GS" ;//"GS" for GS implemented, "GSLIB" for GS from library, "Schnorr" for Schnorr proof in user registration
    let submission_proof_type = "GS"; //"GSLIB", "GS" in submission,
    
    let (signature_scheme_type, mut crs_ur, crs_type, group1, group2) = setup(scheme, ur_proof_type, submission_proof_type, &mut rng);
    //RA generation
    let start_ra = Instant::now();
    let ra = RA::<Bls12_381>::new(&signature_scheme_type);
    let pk_ra = ra.get_pk();
    let t_ra = start_ra.elapsed();
    //SA generation
    let start_sa = Instant::now();
    let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
    let pk_sa = sa.get_pk();
    let vid = sa.get_vid();
    let t_sa = start_sa.elapsed();
    //CRS generation
    let start_crs = Instant::now();
    //GS library : crs for RA and SA signature possession proofs, crs2 for token validity proof, crs_exp is None
    //GS implemented: crs and crs2 for RA and SA signature possession proofs, crs_exp for token validity proof
    let crs = generate_crs(&mut rng, &crs_type, &group1);
    let crs2 = generate_crs(&mut rng, &crs_type, &group2);
    let crs_exp: CRS<Bls12_381> = generate_crs(&mut rng, &crs_type, &group2);
    //ots scheme : LD or P 
    //let ots_scheme = OTSignatureSchemeType::LD(LDOTSignatureScheme {  });
    let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {  });      
    let t_crs = start_crs.elapsed();

    //User
    let start_user = Instant::now();
    let mut user = User::<Bls12_381>::new(&mut rng, &signature_scheme_type,pk_ra, pk_sa, vid);
    let t_u = start_user.elapsed();

    // User registration    
    let start_ur1 = Instant::now();
    let user_ra_comm =user.user_registration_1(&crs_ur, &mut rng);
    let t_ur1= start_ur1.elapsed();
    let s_ur1 = (size_of_val(&user_ra_comm)+vec_size(&user_ra_comm.pk)+vec_size(&user_ra_comm.id)+vec_size(&user_ra_comm.proof))*8;
    let start_ra2 = Instant::now();
    let user_racomm2 = ra.user_registration_2(&mut rng,&user_ra_comm, &crs_ur).unwrap();
    let t_ur2 = start_ra2.elapsed();
    let s_ur2 = (size_of_val(&user_racomm2)+vec_size(&user_racomm2.signature))*8;
    let start_user2 = Instant::now();
    let signature_ra =SignatureType::deserialize(&user_racomm2.signature, &signature_scheme_type);
    user.user_registration_3(&signature_ra).unwrap();
    let t_ur3 = start_user2.elapsed();

    // Survey registration
    let start_sa2 = Instant::now();
    let signature_sa_compressed = sa.survey_registration(&mut rng,user.get_gid());
    let signature_sa = SignatureType::deserialize(&signature_sa_compressed.signature, &signature_scheme_type);
    user.set_signature_sa(&signature_sa);
    let t_sr = start_sa2.elapsed();
    let s_sr = (size_of_val(&signature_sa_compressed)+vec_size(&signature_sa_compressed.signature))*8;


    // Authorised
    let start_auth = Instant::now();
    authorized(&pk_sa, user.get_gid(), &sa.gvid, &signature_sa);
    let t_auth = start_auth.elapsed();

    // Submission
    let start_sub = Instant::now();
    let submission = user.submission( &mut rng, &crs, &crs2, &crs_exp, &ots_scheme);
    let t_sub = start_sub.elapsed();
    let start_sub2 = Instant::now();
    sa.submission_check(&submission, &crs, &crs2, &crs_exp).unwrap();
    let t_sub2 = start_sub2.elapsed();

    
    if (print_time){
        let t_user = t_u+t_ur1 + t_ur3 + t_sub;
        let t_ra_tot = t_ra + t_ur2;
        let t_sa_tot = t_sa + t_sr + t_sub2;
        let t_tot= t_user + t_ra_tot + t_sa_tot + t_crs +t_auth;
        if (print_header){
            println!("Exp. type, RA setup, SA setup, User setup, CRS generation, UR1, UR2, UR3, Survey registration, Authorisation, Submission, Submission check, User total, RA total, SA total, Total (ms)"); 
        }
        
        println!("{}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",exp_type, t_ra.as_millis(), t_sa.as_millis(), t_u.as_millis(), t_crs.as_millis(), t_ur1.as_millis(), t_ur2.as_millis(), t_ur3.as_millis(), t_sr.as_millis(), t_auth.as_millis(), t_sub.as_millis(), t_sub2.as_millis(), t_user.as_millis(), t_ra_tot.as_millis(), t_sa_tot.as_millis(), t_tot.as_millis());  
    }  
    
    if (print_size){
        
        let mut s_sub=0;
        if (scheme=="AS"){
            let s=submission.as_value();
            let sp = s.proof.gs_value().gs_value();
            s_sub = (size_of_val(&submission)+vec_size(&s.pk_commitment)+vec_size(&s.token)+vec_size(&s.ovk)+vec_size(&s.ots)+vec_size(&sp.0)+vec_size(&sp.1)+vec_size(&sp.2)+vec_size(&sp.3)+vec_size(&sp.4))*8;
        }else if (scheme =="AN") {
                let s2= submission.an_value();
                s_sub = (size_of_val(&submission)+size_of_val(&s2.token)+size_of_val(&s2.s2)+size_of_val(&s2.s4)+size_of_val(&s2.proof)+vec_size(&s2.proof.e1)+vec_size(&s2.proof.e2)+vec_size(&s2.proof.e3)+vec_size(&s2.proof.challenge)+vec_size(&s2.proof.z1)+vec_size(&s2.proof.z2)+vec_size(&s2.proof.z3)+vec_size(&s2.proof.z4))*8;

        }   
        let s_ur_tot = s_ur1 + s_ur2;
        let mut s_tot = s_ur1 + s_ur2 + s_sr +s_sub;

        if (print_header){
            println!("Exp. type, UR1, UR2, UR_tot, SR, Submission, Total size (bits)");
        }
        println!("{}, {}, {}, {}, {}, {}, {}",exp_type, s_ur1, s_ur2, s_ur_tot, s_sr, s_sub, s_tot);
    }

}

