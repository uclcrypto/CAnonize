use criterion::{Criterion,};


use ark_std::{test_rng, hint::black_box as bb};
use ark_bls12_381::{Bls12_381};


use groth_sahai::{AbstractCrs, CRS};
//type GT = PairingOutput<Bls12_381>;

//use crate::sps_improved::SignatureScheme;
//use ark_bls12_381::Fr as ScalarField;

use anonymous_survey::utils::signature::sps_improved::*;

use anonymous_survey::utils::utils::*;

use anonymous_survey::survey_authority::*;
use anonymous_survey::registration_authority::*;
fn setup(){
        let signature_scheme_type: SignatureSchemeType = bb(SignatureSchemeType::SPSImp(bb(SPSImpSignatureScheme{})));
    //let signature_scheme_type: SignatureSchemeType = SignatureSchemeType::BB(BBSignatureScheme{});
    //RA generation
    let ra = bb(RA::<Bls12_381>::new(bb(&signature_scheme_type)));
    let ra = bb(ra);
    let pk_ra = bb(ra.get_pk());
    //SA generation
    let sa = bb(SA::<Bls12_381>::new(bb(pk_ra), bb(&signature_scheme_type)));
    let sa = bb(sa);
    let _pk_sa = bb(sa.get_pk());
    let _vid = bb(sa.get_vid());

    //CRS generation
    let rng = bb(test_rng());
    let mut rng = bb(rng);
    //let mut rng = bb(rand::rng());
    let rng2 = bb(test_rng());
    let mut rng2 = bb(rng2);
    let rng3 = bb(test_rng());
    let mut rng3 = bb(rng3);
    bb(CRS::<Bls12_381>::generate_crs(bb(&mut rng)));
    //let crs = bb(crs);
    let _crs2 = bb(CRS::<Bls12_381>::generate_crs(bb(&mut rng2)));
    //let crs2 = bb(crs2);
    let _crs3 = bb(CRS::<Bls12_381>::generate_crs(bb(&mut rng3)));
    //let crs3 = bb(crs3);
}
pub fn criterion_benchmark_sep(c: &mut Criterion) {
    let mut group = c.benchmark_group("sample-size-example");
    group.sample_size(40);
    group.bench_function("AS setup", |b|
                 b.iter(|| 
                    {//anonymous_survey_benchmark();  
                        std::hint::black_box(setup()); 
                    }));
    
}