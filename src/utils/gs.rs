use ark_ec::{ pairing::Pairing, 
    PrimeGroup,};
use ark_std::{UniformRand, test_rng, rand::Rng};
use ark_ff::{ Zero};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::{ utils::signature::sps_improved::{SPSImpPublicKey, SPSImpSignature}, utils::utils::CRS};

/// CRS in G1
#[derive(Debug,Copy, Clone)]
pub struct CrsG1<E:Pairing>{
    g11: E::G1,
    g12: E::G1,
    g21: E::G1,
    g22: E::G1, 
}
impl<E:Pairing> CrsG1<E> {
    pub fn new<R:Rng>(rng: &mut R)->CRS<E> {
        let g11 = E::G1::rand(rng);
        let g12 = E::G1::rand(rng);
        let g21 = E::G1::rand(rng);
        let g22 = E::G1::rand(rng);
        CRS::GS1(
            CrsG1{
                g11,
                g12,
                g21,
                g22,
            }
        )
    }
}
/// CRS in G2
#[derive(Debug,Copy, Clone)]
pub struct CrsG2<E:Pairing>{
    pub g11: E::G2,
    pub g12: E::G2,
    pub g21: E::G2,
    pub g22: E::G2, 
}
impl<E:Pairing> CrsG2<E> {
    pub fn new<R:Rng>(rng: &mut R)->CRS<E> {
        let g11 = E::G2::rand(rng);
        let g12 = E::G2::rand(rng);
        let g21 = E::G2::rand(rng);
        let g22 = E::G2::rand(rng);
        CRS::GS2(
            CrsG2{
                g11,
                g12,
                g21,
                g22,
            }
        )
    }
    pub fn new_half<R:Rng>(rng: &mut R)->CRS<E> {
        let g11 = E::G2::zero();
        let g12 = E::G2::zero();
        let g21 = E::G2::rand(rng);
        let g22 = E::G2::rand(rng);
        CRS::GS2(
            CrsG2{
                g11,
                g12,
                g21,
                g22,
            }
        )
    }
}
/// Commitment to an element in G1
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentG1<E:Pairing>{
    com1: E::G1,
    com2: E::G1,
}
impl<E:Pairing> CommitmentG1<E> {
    pub fn commit<R: Rng>(rng: &mut R, crs: &CrsG1<E>, value: &E::G1) ->(Self,[E::ScalarField;2]) {
        let r1 = E::ScalarField::rand(rng);
        let r2 = E::ScalarField::rand(rng);
        let com1 = crs.g11 * r1 + crs.g21 * r2 ;
        let com2 = *value + crs.g12 * r1 + crs.g22 * r2;
        (CommitmentG1{
            com1,
            com2,
        }, [r1, r2])
    }
}
/// Commitment in G2
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitmentG2<E:Pairing>{
    com1: E::G2,
    com2: E::G2,
}
impl<E:Pairing> CommitmentG2<E> {
    /// commitment to an element in G2
    pub fn commit(crs: &CrsG2<E>, value: &E::G2) ->(Self,[E::ScalarField;2]) {
        let mut rng = test_rng();
        let r1 = E::ScalarField::rand(&mut rng);
        let r2 = E::ScalarField::rand(&mut rng);
        let com1 = crs.g11 * r1 + crs.g21 * r2 ;
        let com2 = *value + crs.g12 * r1 + crs.g22 * r2;
        (CommitmentG2{
            com1,
            com2,
        }, [r1, r2])
    }
    /// commitment to an element in Zq
    pub fn commit_exp(crs: &CrsG2<E>, value: &E::ScalarField) ->(Self,E::ScalarField) {
        let mut rng = test_rng();
        let r = E::ScalarField::rand(&mut rng);
        let com1 = crs.g21 * (*value) + crs.g11 * r ;
        let com2 = crs.g11*(*value) + crs.g22 * (*value) + crs.g12 * r;
        (CommitmentG2{
            com1,
            com2,
        }, r)
    }
}
/// GS proof elements in user registration
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
struct ProofU<E:Pairing>{
    p: E::G1,
}
impl<E:Pairing> ProofU<E> {
    fn new(randomness: &E::ScalarField) ->Self {       

        let p = E::G1::generator()*(*randomness);
        ProofU{
            p,
        }
    }
}

/// GS proof elements in submission: valid RA signature equation 1
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
struct ProofG1RA1<E:Pairing>{
    p1: E::G2,
    p2: E::G2,
}
impl<E:Pairing> ProofG1RA1<E> {
    fn new(randomness: &[&[E::ScalarField;2]; 7], pk_ra: &SPSImpPublicKey<E>) ->Self {
        

        let p1 = pk_ra.hk1a*randomness[0][0] + 
                                     pk_ra.hk2a*randomness[1][0] + 
                                     pk_ra.hk3a*randomness[2][0] +
                                     pk_ra.hk4a*randomness[3][0] +
                                     pk_ra.hk5a*randomness[4][0] + 
                                     pk_ra.hk6a*randomness[5][0] -
                                     pk_ra.ha*randomness[6][0];
        let p2 = pk_ra.hk1a*randomness[0][1] + 
                                     pk_ra.hk2a*randomness[1][1] + 
                                     pk_ra.hk3a*randomness[2][1] +
                                     pk_ra.hk4a*randomness[3][1] +
                                     pk_ra.hk5a*randomness[4][1] + 
                                     pk_ra.hk6a*randomness[5][1] -
                                     pk_ra.ha*randomness[6][1];
        ProofG1RA1{
            p1,
            p2,
        }
    }
}
/// GS proof elements in submission: valid SA signature equation 1
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
struct ProofG1SA1<E:Pairing>{
    p1: E::G2,
    p2: E::G2,
}
impl<E:Pairing> ProofG1SA1<E> {
    fn new(randomness: &[&[E::ScalarField;2]; 6], pk_ra: &SPSImpPublicKey<E>) ->Self {
        

        let p1 = pk_ra.hk1a*randomness[0][0] + 
                                     pk_ra.hk3a*randomness[1][0] +
                                     pk_ra.hk4a*randomness[2][0] +
                                     pk_ra.hk5a*randomness[3][0] + 
                                     pk_ra.hk6a*randomness[4][0] -
                                     pk_ra.ha*randomness[5][0];
        let p2 = pk_ra.hk1a*randomness[0][1] + 
                                     pk_ra.hk3a*randomness[1][1] +
                                     pk_ra.hk4a*randomness[2][1] +
                                     pk_ra.hk5a*randomness[3][1] + 
                                     pk_ra.hk6a*randomness[4][1] -
                                     pk_ra.ha*randomness[5][1];
        ProofG1SA1{
            p1,
            p2,
        }
    }
}
/// GS proof elements in submission: valid RA/SA signature equation 2
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
struct ProofG2<E:Pairing>{
    p1_11: E::G1,
    p1_12: E::G1,
    p1_21: E::G1,
    p1_22: E::G1,
    p2_11: E::G2,
    p2_12: E::G2,
    p2_21: E::G2,
    p2_22: E::G2,
}
impl<E:Pairing> ProofG2<E> {
    fn new(crs2: &CrsG2<E>, crs1: &CrsG1<E>, tau: &E::G2, rho:& E::G1,r_tau: &[E::ScalarField; 2], r_rho: &[E::ScalarField; 2], r_psi: &[E::ScalarField; 2]) ->Self {
        let g2=E::G2::generator();
        let rng = &mut test_rng();
        let nu = E::ScalarField::rand(rng);
        let nu1 = E::ScalarField::rand(rng);
        let nu2 = E::ScalarField::rand(rng);
        let nu3 = E::ScalarField::rand(rng);

        let p2_11 = crs2.g11*(r_tau[0]*r_rho[0]-nu) + crs2.g21*(r_tau[1]*r_rho[0]-nu2);
        let p2_12 = *tau*r_rho[0]+g2*(-r_psi[0])+crs2.g12*(r_tau[0]*r_rho[0]-nu) + crs2.g22*(r_tau[1]*r_rho[0]-nu2);

        let p2_21 = crs2.g11*(r_tau[0]*r_rho[1]-nu1) + crs2.g21*(r_tau[1]*r_rho[1]-nu3);
        let p2_22 = *tau*r_rho[1]+g2*(-r_psi[1])+crs2.g12*(r_tau[0]*r_rho[1]-nu1) + crs2.g22*(r_tau[1]*r_rho[1]-nu3);

        let p1_11=crs1.g11*nu+crs1.g21*nu1;
        let p1_12= *rho*r_tau[0] + crs1.g12*nu+ crs1.g22*nu1;
        let p1_21=crs1.g11*nu2+crs1.g21*nu3;
        let p1_22= *rho*r_tau[1]+crs1.g12*nu2+crs1.g22*nu3;
        ProofG2{
            p1_11,
            p1_12,
            p1_21,
            p1_22,
            p2_11,
            p2_12,
            p2_21,
            p2_22,
        }
    }
    
}
/// GS proof elements in submission: valid token in c_pk and in C
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
struct ProofG1exp<E:Pairing>{
    p1: E::G1,
    p2: E::G1,
    p3: E::G1,
}
impl<E:Pairing> ProofG1exp<E> {
    fn new(crs1: &CrsG1<E>,rho_sid: &E::ScalarField, rho_r1: &E::ScalarField, rho_r2: &E::ScalarField, hash : &E::G1) ->Self {
        
        let p1 = crs1.g11*(*rho_r1) + crs1.g21*(*rho_r2);
        let p2 =E::G1::generator()*(*rho_sid) + crs1.g12*(*rho_r1) + crs1.g22*(*rho_r2);
        let p3= *hash*(*rho_sid);
        ProofG1exp{
            p1,
            p2,
            p3,
        }
    }
}

/// GS proof user registration
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct GSU<E:Pairing>{
    commitment: CommitmentG2<E>,
    proof: ProofU<E>,
}
impl<E:Pairing> GSU<E> {
    pub fn new(crs: &CrsG2<E>, sid: &E::ScalarField)->Self {
        let (c_sid, r_sid) = CommitmentG2::commit_exp(crs, sid);
        let proof = ProofU::new(&r_sid);
        GSU { commitment: c_sid, proof }
    }
    pub fn verify(&self, crs: &CrsG2<E>, pk: &E::G1) -> bool {
        let g = E::G1::generator();
        let lhs1 = E::pairing(g, self.commitment.com1);
        let rhs1 = E::pairing(pk, crs.g21) + E::pairing(self.proof.p, crs.g11);
        if lhs1 != rhs1 {
            return false
        }
        let lhs2 = E::pairing(g, self.commitment.com2);
        let rhs2 = E::pairing(pk, crs.g11+crs.g22) + E::pairing(self.proof.p, crs.g12);
        
        //let target = E::pairing(E::G1::generator(), pk_ra.hka);
        if lhs2 !=rhs2 {
            return false
        }
        true
    }
    
}
///GS proof submission: valid RA signature equation 1
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct GSRA11<E:Pairing>{
    pub commitments: [CommitmentG1<E>;7],
    proofs: ProofG1RA1<E>,

}
impl<E:Pairing> GSRA11<E> {
    pub fn new<R: Rng>(rng: &mut R, crs: &CrsG1<E>, pk_ra: &SPSImpPublicKey<E>, signature_ra: &SPSImpSignature<E>, gid :& E::G1, pk: &E::G1)->(Self, [E::ScalarField;2],[E::ScalarField;2], [E::ScalarField;2]) {
        let (c_gid, r_gid) = CommitmentG1::commit(rng, crs, gid);
        let (c_pk, r_pk) = CommitmentG1::commit(rng, crs, pk);
        let (c_rho,r_rho) = CommitmentG1::commit(rng, crs, &signature_ra.rho);
        let (c_rho_hat, r_rho_hat) = CommitmentG1::commit(rng, crs, &signature_ra.rho_hat);
        let (c_psi, r_psi) = CommitmentG1::commit(rng, crs, &signature_ra.psi);
        let (c_gamma, r_gamma) = CommitmentG1::commit(rng, crs, &signature_ra.gamma);
        let (c_pi, r_pi) = CommitmentG1::commit(rng, crs, &(signature_ra.pi));
        let proof = ProofG1RA1::new(&[&r_gid, &r_pk, &r_rho, &r_rho_hat, &r_psi, &r_gamma, &r_pi], pk_ra);

        (GSRA11{
            commitments: [c_gid, c_pk, c_rho, c_rho_hat, c_psi, c_gamma,  c_pi],
            proofs: proof,
        }, r_gid, r_rho, r_psi)
    }
    pub fn verify(&self, crs: &CrsG1<E>, pk_ra: &SPSImpPublicKey<E>) -> bool {
        let lhs1 = E::pairing(self.commitments[0].com1, pk_ra.hk1a) 
                                   + E::pairing(self.commitments[1].com1, pk_ra.hk2a)
                                   + E::pairing(self.commitments[2].com1, pk_ra.hk3a)
                                   + E::pairing(self.commitments[3].com1, pk_ra.hk4a)
                                   + E::pairing(self.commitments[4].com1, pk_ra.hk5a)
                                   + E::pairing(self.commitments[5].com1, pk_ra.hk6a)
                                   - E::pairing(self.commitments[6].com1, pk_ra.ha);
        let rhs1 = E::pairing(crs.g11, self.proofs.p1)                                                            
                                   + E::pairing(crs.g21, self.proofs.p2);
                                                            
        if lhs1 != rhs1 {
            return false
        }
        let lhs2 = E::pairing(self.commitments[0].com2, pk_ra.hk1a) 
                                   + E::pairing(self.commitments[1].com2, pk_ra.hk2a)
                                   + E::pairing(self.commitments[2].com2, pk_ra.hk3a)
                                   + E::pairing(self.commitments[3].com2, pk_ra.hk4a)
                                   + E::pairing(self.commitments[4].com2, pk_ra.hk5a)
                                   + E::pairing(self.commitments[5].com2, pk_ra.hk6a)
                                   - E::pairing(self.commitments[6].com2, pk_ra.ha);
        let rhs2 = E::pairing(crs.g12, self.proofs.p1)
                                    + E::pairing(crs.g22, self.proofs.p2);
                                                            
        let target = E::pairing(E::G1::generator(), pk_ra.hka);
        if lhs2 != -target+rhs2 {
            return false
        }
        true
    }
    
}
/// GS proof submission: valid SA signature equation 2
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct GSRA12<E:Pairing>{
    commitments: CommitmentG2<E>,
    proofs: ProofG2<E>,

}
impl<E:Pairing> GSRA12<E> {
    pub fn new(crs1: &CrsG1<E>, crs2: &CrsG2<E>, signature_ra: &SPSImpSignature<E>, r_rho: &[E::ScalarField;2], r_psi: &[E::ScalarField;2])->Self {
        
        let (c_tau,r_tau) = CommitmentG2::commit(crs2, &signature_ra.tau);
        let p_tau = ProofG2::new(crs2, crs1, &signature_ra.tau, &signature_ra.rho,&r_tau, r_rho,r_psi,);
        
        GSRA12{
            commitments: c_tau,
            proofs: p_tau,
        }
    }

    pub fn verify(&self, crs2: &CrsG2<E>, crs1: &CrsG1<E>, c_rho: &CommitmentG1<E>, c_psi: &CommitmentG1<E>) -> bool {
        let lhs11 = E::pairing(c_rho.com1, self.commitments.com1);
        let rhs11 = E::pairing(crs1.g11, self.proofs.p2_11)+ E::pairing(crs1.g21, self.proofs.p2_21)+ E::pairing(self.proofs.p1_11, crs2.g11)+ E::pairing(self.proofs.p1_21, crs2.g21);
        if lhs11 != rhs11 {
            return false
        }
        let g2=E::G2::generator();
        let lhs12 = E::pairing(c_rho.com1, self.commitments.com2)+E::pairing(c_psi.com1, -g2);
        let rhs12 = E::pairing(crs1.g11, self.proofs.p2_12)+ E::pairing(crs1.g21, self.proofs.p2_22)+ E::pairing(self.proofs.p1_11, crs2.g12)+ E::pairing(self.proofs.p1_21, crs2.g22);
        if lhs12 != rhs12 {
            return false
        }
        let lhs21 = E::pairing(c_rho.com2, self.commitments.com1);
        let rhs21 = E::pairing(crs1.g12, self.proofs.p2_11)+ E::pairing(crs1.g22, self.proofs.p2_21)+ E::pairing(self.proofs.p1_12, crs2.g11)+ E::pairing(self.proofs.p1_22, crs2.g21);
        if lhs21 != rhs21 {
            return false
        }
        let lhs22 = E::pairing(c_rho.com2, self.commitments.com2)+E::pairing(c_psi.com2, -g2);
        let rhs22 = E::pairing(crs1.g12, self.proofs.p2_12)+ E::pairing(crs1.g22, self.proofs.p2_22)+ E::pairing(self.proofs.p1_12, crs2.g12)+ E::pairing(self.proofs.p1_22, crs2.g22);
        if lhs22 != rhs22 {
            return false
        }
        true

    }
}
///GS proof submission: valid SA signature equation 1
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct GSSA11<E:Pairing>{
    pub commitments: [CommitmentG1<E>;5],
    proofs: ProofG1SA1<E>,
}
impl<E:Pairing> GSSA11<E> {
    pub fn new<R: Rng>(rng: &mut R, crs: &CrsG1<E>, pk_sa: &SPSImpPublicKey<E>, signature_sa: &SPSImpSignature<E>, r_gid :& [E::ScalarField;2])->(Self, [E::ScalarField;2], [E::ScalarField;2]) {
        let (c_rho,r_rho) = CommitmentG1::commit(rng, crs, &signature_sa.rho);
        let (c_rho_hat, r_rho_hat) = CommitmentG1::commit(rng, crs, &signature_sa.rho_hat);
        let (c_psi, r_psi) = CommitmentG1::commit(rng, crs, &signature_sa.psi);
        let (c_gamma, r_gamma) = CommitmentG1::commit(rng, crs, &signature_sa.gamma);
        let (c_pi, r_pi) = CommitmentG1::commit(rng, crs, &(signature_sa.pi));
        let proof = ProofG1SA1::new(&[r_gid, &r_rho, &r_rho_hat, &r_psi, &r_gamma, &r_pi], pk_sa);
        
        (GSSA11{
            commitments: [c_rho, c_rho_hat, c_psi, c_gamma,  c_pi],
            proofs: proof,
        }, r_rho, r_psi)
    }
    pub fn verify(&self, crs: &CrsG1<E>, pk_ra: &SPSImpPublicKey<E>, c_gid : &CommitmentG1<E>, vid: &E::G1) -> bool {
        let lhs1 = E::pairing(c_gid.com1, pk_ra.hk1a) 
                                   + E::pairing(self.commitments[0].com1, pk_ra.hk3a)
                                   + E::pairing(self.commitments[1].com1, pk_ra.hk4a)
                                   + E::pairing(self.commitments[2].com1, pk_ra.hk5a)
                                   + E::pairing(self.commitments[3].com1, pk_ra.hk6a);
        let rhs1 =E::pairing(self.commitments[4].com1, pk_ra.ha)
                                   + E::pairing(crs.g11, self.proofs.p1)
                                   + E::pairing(crs.g21, self.proofs.p2);
                                                            
        if lhs1 != rhs1 {
            return false
        }
        let lhs2 = E::pairing(c_gid.com2, pk_ra.hk1a) 
                                   + E::pairing(self.commitments[0].com2, pk_ra.hk3a)
                                   + E::pairing(self.commitments[1].com2, pk_ra.hk4a)
                                   + E::pairing(self.commitments[2].com2, pk_ra.hk5a)
                                   + E::pairing(self.commitments[3].com2, pk_ra.hk6a);
                                   
        let rhs2 = E::pairing(self.commitments[4].com2, pk_ra.ha)
                                   + E::pairing(crs.g12, self.proofs.p1)
                                   + E::pairing(crs.g22, self.proofs.p2);
                                                            
        let target = E::pairing(E::G1::generator(), pk_ra.hka)+ E::pairing(vid, pk_ra.hk2a);
        if lhs2 +target !=rhs2 {
            return false
        }
        true
    }
    
}
///GS proof submission: valid sid in c_pk and C
#[derive(Debug,CanonicalSerialize, CanonicalDeserialize)]
pub struct GSSA3<E:Pairing>{
    commitments: [CommitmentG2<E>;3],
    proofs: ProofG1exp<E>,

}
impl<E:Pairing> GSSA3<E> {
    pub fn new(crs1: &CrsG1<E>, crs2: &CrsG2<E>, sid: &E::ScalarField, r1: &E::ScalarField, r2: &E::ScalarField, hash: &E::G1 )->Self {
        
        let (c_sid,r_sid) = CommitmentG2::commit_exp(crs2, sid);
        let (c_r1,r_r1) = CommitmentG2::commit_exp(crs2, r1);
        let (c_r2,r_r2) = CommitmentG2::commit_exp(crs2, r2);
        let proofs = ProofG1exp::new(crs1, &r_sid, &r_r1,&r_r2,hash);
        
        GSSA3{
            commitments: [c_sid, c_r1, c_r2],
            proofs: proofs,
        }
    }
    pub fn verify(&self, crs1: &CrsG1<E>, crs2: &CrsG2<E>, hash: &E::G1, token: &E::G1,c_pk: &CommitmentG1<E>) -> bool {
        let [c_sid, c_r1, c_r2] = &self.commitments;
        let lhs11 = E::pairing(crs1.g11,c_r1.com1)+ E::pairing(crs1.g21,c_r2.com1);
        let rhs11 = E::pairing(c_pk.com1, crs2.g21)+ E::pairing(self.proofs.p1, crs2.g11);
        if lhs11 != rhs11 {
            return false
        }

        let lhs12 = E::pairing(crs1.g11,c_r1.com2)+ E::pairing(crs1.g21,c_r2.com2);
        let rhs12 = E::pairing(c_pk.com1, crs2.g11+crs2.g22)+ E::pairing(self.proofs.p1, crs2.g12);
        if lhs12 != rhs12 {
            return false
        }

        let lhs21=E::pairing(E::G1::generator(), c_sid.com1)+E::pairing(crs1.g12,c_r1.com1)+ E::pairing(crs1.g22,c_r2.com1);
        let rhs21 = E::pairing(c_pk.com2, crs2.g21)+ E::pairing(self.proofs.p2, crs2.g11);
        if lhs21 != rhs21 {
            return false
        }
        let lhs22 = E::pairing(E::G1::generator(), c_sid.com2)+E::pairing(crs1.g12,c_r1.com2)+ E::pairing(crs1.g22,c_r2.com2);
        let rhs22 = E::pairing(c_pk.com2, crs2.g11+crs2.g22)+ E::pairing(self.proofs.p2, crs2.g12);
        if lhs22 != rhs22 {
            return false
        }

        let lhs31 = E::pairing(hash, c_sid.com1);
        let rhs31 = E::pairing(token,crs2.g21)+ E::pairing(self.proofs.p3, crs2.g11);
        if lhs31 != rhs31 {
            return false
        }

        let lhs32 = E::pairing(hash, c_sid.com2);
        let rhs32 = E::pairing(token,crs2.g11+crs2.g22)+ E::pairing(self.proofs.p3, crs2.g12);
        if lhs32 != rhs32 {
            return false
        }
        true

    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use crate::utils::signature::sps_improved::*;
    use crate::utils::utils::*;
    use crate::survey_authority::*;
    use crate::registration_authority::*;
    use ark_ec::{hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve}, 
    };
    use crate::DOMAIN;
    use sha2::{ Sha256};
    use ark_bls12_381::{G1Projective as G1, g1::Config as G1Config, Fr as ScalarField };
    use ark_ff::field_hashers::DefaultFieldHasher;
    #[test]
    fn test_gs_ra1() {
        let signature_scheme_type = SignatureSchemeType::SPSImp(SPSImpSignatureScheme{});
        let ra = RA::<Bls12_381>::new(&signature_scheme_type);
        let pk_ra = ra.get_pk();
        //SA generation
        let sa = SA::<Bls12_381>::new(pk_ra, &signature_scheme_type);
        let pk_sa = sa.get_pk();
        //CRS generation
        let mut rng = test_rng();
        let crs_ra1 = CrsG1::<Bls12_381>::new(&mut rng);
        let crs_ra2 = CrsG2::<Bls12_381>::new(&mut rng);
        let crs_exp2 = CrsG2::<Bls12_381>::new(&mut rng);   

        let crs3 = CrsG2::<Bls12_381>::new(&mut rng);
        //User
        // User registration
        //let user_ra_comm = user.user_registration_1();
        let sid = ScalarField::rand(&mut rng);
        let pk = G1::generator()*sid;
        let id = G1::rand(&mut rng);
        let proof = ProofType::GSRA(GSU::<Bls12_381>::new(&crs3.gs2_value(), & sid));
        let mut id_compressed = Vec::new();
        let mut pk_compressed = Vec::new();
        let mut proof_compressed = Vec::new();
        id.serialize_compressed(&mut id_compressed).unwrap();
        pk.serialize_compressed(&mut pk_compressed).unwrap();
        proof.gsu_value().serialize_compressed(&mut proof_compressed).unwrap();
        let user_ra_comm= UserRAComm { id: id_compressed, pk: pk_compressed, proof: proof_compressed, proof_type: Proofs::GSRA };

        let signature_ra = ra.user_registration_2(&mut rng,&user_ra_comm,&crs3).unwrap();
        let signature_ra = SPSImpSignature::<Bls12_381>::deserialize_compressed(&*signature_ra.signature).unwrap();

        let crs_ra1_value = match &crs_ra1 {
            CRS::GS1(c) => c,
            _ => panic!("Wrong CRS type"),
        };

        let (proof_ra1, r_gid,r_rho, r_psi) = GSRA11::<Bls12_381>::new(&mut rng, &crs_ra1_value,pk_ra.sps_imp_value(), &signature_ra,&id, &pk);
        let crs_ra1_value = match &crs_ra1 {
            CRS::GS1(c) => c,
            _ => panic!("Wrong CRS type"),
        };
        assert!(proof_ra1.verify(&crs_ra1_value, pk_ra.sps_imp_value()));

        let crs_ra2_value = match &crs_ra2 {
            CRS::GS2(c) => c,
            _ => panic!("Wrong CRS type"),
        };

        let proof_ra2 = GSRA12::<Bls12_381>::new(&crs_ra1_value, &crs_ra2_value, &signature_ra, &r_rho,  &r_psi);
        assert!(proof_ra2.verify(&crs_ra2_value, &crs_ra1_value, &proof_ra1.commitments[2], &proof_ra1.commitments[4]));

        // Survey registration
        let signature_sa = sa.survey_registration(&mut rng,&id);
        // Authorised
        let signature_sa = SignatureType::deserialize(&signature_sa.signature, &SignatureSchemeType::SPSImp(SPSImpSignatureScheme{}));
        authorized(&pk_sa, &id, &sa.gvid, &signature_sa);
        let (proof_sa1, r_rho2, r_psi2) = GSSA11::<Bls12_381>::new(&mut rng, &crs_ra1_value,pk_sa.sps_imp_value(), signature_sa.sps_imp_value(),&r_gid);
        assert!(proof_sa1.verify(&crs_ra1_value, pk_sa.sps_imp_value(), &proof_ra1.commitments[0], &sa.gvid));

        let proof_sa2 = GSRA12::<Bls12_381>::new(&crs_ra1_value, &crs_ra2_value, &signature_sa.sps_imp_value(), &r_rho2,  &r_psi2);
        assert!(proof_sa2.verify(&crs_ra2_value, &crs_ra1_value, &proof_sa1.commitments[0], &proof_sa1.commitments[2]));
        let sid = ScalarField::rand(&mut rng);
        let pk = G1::generator()*sid;
        let (pk_prime, [r1,r2]) = CommitmentG1::commit(&mut rng, &crs_ra1_value, &pk);
        let g1_mapper = MapToCurveBasedHasher::<
            G1,
            DefaultFieldHasher<Sha256, 256>,
            WBMap<G1Config>,
        >::new(DOMAIN)
        .unwrap();
        let crs_exp2_value = match &crs_exp2 {
            CRS::GS2(c) => c,
            _ => panic!("Wrong CRS type"),
        };
        let vid = sa.get_vid();
        let hash = g1_mapper.hash(vid.to_string().as_bytes()).unwrap();
        
        let token = hash * sid; 
        let proof_exp = GSSA3::<Bls12_381>::new(&crs_ra1_value, &crs_exp2_value, &sid, &r1, &r2, &hash.into());
        assert!(proof_exp.verify(&crs_ra1_value, &crs_exp2_value, &hash.into(), &token, &pk_prime));

    }
    #[test]
    fn test_gs_u() {
        let mut rng = test_rng();
        let sid= ScalarField::rand(&mut rng);
        let pk = G1::generator()*sid;
        let crs2 = CrsG2::<Bls12_381>::new(&mut rng);
        let crs2_value = match &crs2 {
            CRS::GS2(c) => c,
            _ => panic!("Wrong CRS type"),
        };
        let proof_u = GSU::<Bls12_381>::new( &crs2_value, &sid);
        assert!(proof_u.verify(&crs2_value, &pk));
    }

        
    
}