# CAnonize - Compact Anonymous Survey Protocol 

A Rust implementation of the CAnonize protocol for anonymous surveys, providing simpler assumptions and improved efficiency compared to the state-of-the-art [Anonize](https://eprint.iacr.org/2015/681) protocol. This implementation provides privacy-preserving surveys where users can submit unlinkable responses anonymously while preventing duplicate submissions and preventing submissions from unregistered and unauthorized users.

We also provide an implementation of Anonize for comparison. To ensure a fair comparison, the same libraries and optimizations were used for both implementations and no batching techniques were employed that could give an advantage to CAnonize. The proposed implementation of Anonize uses a transform due to Fischlin instead of the less efficient transform due to Pass used in the Anonize paper.

## Anonymous survey scheme

A survey scheme involves three types of entities: a single registration authority (RA), survey authorities (SA), and users. The RA is responsible for maintaining a list of registered users. 
Any user wanting to organize a survey can assume the role of the SA. Each user is identified by their public $id$.

First, the user registers to the RA and receives a credential. 
Second, the SA produce a list of survey credentials for the users that are authorized to take part in the survey the SA is creating.
Then, the user creates a submission containing:
- the answer to the survey
- proofs that he is a registered and authorized user
- a token that is unlinkable to the user and which unique for a given survey and a given user. 

If the submission is valid, the SA accepts the submission and replaces any previous submission with the same token.

The Auth() procedure allows checking if a user is authorized to participate in a given survey.


## 🚀 Getting Started

### Prerequisites

- Rust 1.85 or later (edition 2024). Please refer to [here](https://rust-lang.org/tools/install/) for installing Rust.
- (Docker 29.4.1 or later)

### Installation

1. Clone the repository 
```bash
git clone git@github.com:uclcrypto/CAnonize.git
```

2. Build the project:
```bash
cargo build --release
```

3. (If you want to run the Docker image provided:)
```bash
docker build -t canonize .
```

## 🏃 Usage

### Running the Protocols
This implementation allows running the CAnonize and Anonize protocols with one registration authority, one survey authority creating one survey and one user submitting one answer.
#### Run the proposed CAnonize protocol:
```bash
cargo run --release AS
```

#### Run the Anonize protocol for comparison:
```bash
cargo run --release AN
```

### Output Format

The program outputs timing measurements in ms:
| Exp. type | RA setup | SA setup | User setup | CRS generation | UR1 | UR2 | UR3 | Survey registration | Authorisation | Submission | Submission check | User total | RA total | SA total | Total (ms) |
| --------- | -------: | -------: | ---------: | -------------: | --: | --: | --: | ------------------: | ------------: | ---------: | ---------------: | ---------: | -------: | -------: | ---------: |
| ours      |       14 |        6 |          0 |             11 |   4 |  13 |  17 |                   2 |            17 |         71 |              199 |         94 |       28 |      208 |        359 |

And the communication cost in bits:
| Exp. type |   UR1 |   UR2 | UR_tot |    SR | Submission | Total size (bits) |
| --------- | ----: | ----: | -----: | ----: | ---------: | ----------------: |
| ours      | 5,056 | 3,456 |  8,512 | 3,456 |     52,544 |            64,512 |

Where:
- `RA_setup: Registration Authority key generation
- `SA_setup`: Survey Authority key generation  
- `User_setup`: User initialization
- `CRS_generation`: Common Reference String generation
- `UR1`, `UR3`: User registration phases for user
- `UR2` : User registration for RA
- `SR`,: Survey registration
- `Authorised`: Authorization check
- `Submission`: Survey submission generation
- `SubmissionCheck`: Submission verification

### Running Benchmarks

Execute the benchmark suite for the timing for the following operations: hashing, hash-to-curve in $G_1$ and $G_2$, pairing evaluation, multiplication in $G_T$, exponentiations in $G_1$ and $G_2$.
```bash
cargo bench
```

The `bench.sh` script computes the median execution time over 50 runs and the communication cost of the CAnonize and Anonize protocols for each survey step. The detailed measurements are stored in the `bench.csv`file.

## 🔧 Technical Overview

This implementation uses:
- **Curve**: BLS12-381 pairing-friendly elliptic curve
- **Framework**: [arkworks](https://arkworks.rs/) ecosystem for elliptic curve and pairing operations
- **Cryptographic Primitives**:
  - Structure-Preserving Signatures (SPS) : implemented
  - Boneh-Boyen (BB) signatures : implemented
  - Groth-Sahai NIZK proofs : implemented
  - One-Time Signatures (Lamport-Diffie and Pedersen-based): implemented
  - Hash-to-Curve functions : from arkworks

## 🔬 Cryptographic Parameters

- **Security Level**: 128 bits 
- **Fischlin Transform**: λ = 32, B = 4 (4-bit zero prefix for hashes) (configurable in `lib.rs`)
- **Curve**: BLS12-381 with groups G1, G2, GT
- **Hash Function**: SHA-256
- **Domain Separator**: `ANONYMOUS_SURVEY_BLS12381:SHA-256_SSWU_RO_POP_`

## Differences compared to Anonize

We provide a new scheme structure using:
- a per-submission generated CRS
- the generic NIZK proof system with Groth--Sahai (GS) proofs which significantly reduces the number of pairing computations required from the user,
- a structure-preserving signature (SPS) scheme which accommodates efficient GS-based verification instead of the partially blind signature scheme used in Anonize,
- the Naor--Pinkas--Reigold PRF which allows the token to be in $G_1$ instead of $G_T$, instead of the the Dodis--Yampolskiy PRF. 

We further modify the user registration and submission steps to guarantee the security of the scheme under the new primitives.

## 📊 Performance Characteristics

The implementation provides significant improvements over Anonize:
- **Simplified assumptions** only requiring hardness of SXDH
- **Reduced computation time** for submission generation and verification
- **Lower communication costs** for user registration and for submission through compressed serialization

Run benchmarks to see detailed performance metrics on your system.

## 📁 Project Structure

```
code/
├── src/
│   ├── lib.rs                      # Library entry point with constants
│   ├── main.rs                     # Main executable for running protocols
│   ├── registration_authority.rs   # RA implementation
│   ├── survey_authority.rs         # SA implementation  
│   ├── as_user.rs                  # User implementation for proposed protocol
│   ├── an_user.rs                  # User implementation for Anonize
│   └── utils/
│       ├── mod.rs                  # Utilities module
│       ├── utils.rs                # Common data structures and helpers
│       ├── errors.rs               # Error types
│       ├── curve_hasher.rs         # Hash-to-curve functionality
│       ├── gs.rs                   # Groth-Sahai proof system
│       ├── signature/
│       │   ├── mod.rs
│       │   ├── pbbb.rs             # Boneh-Boyen signatures
│       │   └── sps_improved.rs     # Structure-Preserving Signatures
│       └── ots/
│           ├── mod.rs
│           ├── ots.rs              # Generic OTS interface
│           ├── lamport_diffie.rs   # Lamport-Diffie OTS
│           └── (Pedersen-based OTS in ots.rs)
├── benches/
│   ├── my_benchmark.rs             # Criterion benchmarks
│   └── benches_sep.rs              # Additional benchmarks
├── Cargo.toml                      # Project dependencies
├── bench.sh                    # Benchmark execution script
├── theo_size_time.py           # Theoretical communication and computational cost
├── Dockerfile   
└── *.csv                       # Benchmark results
```
## 🔑 Key Components

### Entities

1. **Registration Authority (RA)** (`registration_authority.rs`)
   - Registers users in the system
   - Verifies user registration proofs
   - Issues credentials via signatures


2. **Survey Authority (SA)** (`survey_authority.rs`)
   - Creates surveys with unique identifiers
   - Publishes lists of survey credentials for authorized participants
   - Verifies submissions and checks tokens

3. **Users** (`as_user.rs`, `an_user.rs`)
   - Register with RA to obtain user credentials
   - Submit anonymous survey responses to SA
   - Generate zero-knowledge proofs of eligibility

### CAnonize Protocol Flow

1. **System Setup**
   - Initialize pairing groups (BLS12-381)
   - Generate RA and SA signature keys
   - Create Common Reference String (CRS) for Groth-Sahai proofs
   - Initialize users

2. **User Registration** (3 phases)
   - User chooses a secret $sid$, compute $pk=g^{sid}$ and generates proof that pk is well formed
   - RA verifies proof and issues credential signature
   - User stores credential if valid

3. **Survey Registration**
   - SA generates survey identifier $vid$
   - SA creates authorization list of eligible users
   - SA publishes list of signatures on $(vid, pk)$ for authorized participants

4. **Authorization Check**
   - Verify if a user is authorized for a specific survey through the signature in the list published by the SA

5. **Survey Submission**
   - User generates submission with:
     - Survey answer
     - Unlinkable one-time token (prevents duplicate submissions)
     - Per-submission generated CRS
     - Proofs of:
       - Valid RA credential possession
       - Valid SA credential possession
       - Correct token computation
     - One-time signature on token, answer, survey identifier and all proof elements
     - One-time public key

6. **Submission Verification**
   - SA verifies all proofs
   - Verifies the one-time signature
   - Checks for duplicate tokens
   - Accepts or rejects submission
   * This step can be performed by any entity 

## 🔐 Configuration Options

The implementation supports different proof systems and signature schemes:

### Proof Systems
- `GS`: Custom Groth-Sahai implementation
- `GSLIB`: Groth-Sahai from external library (less efficient)
- `Schnorr`: Schnorr proofs (for user registration only)

### Signature Schemes
- **AS Protocol**: SPS (Structure-Preserving Signatures)
- **Anonize**: BB (Boneh-Boyen signatures)

### One-Time Signature Schemes
- `LD`: Lamport-Diffie OTS
- `P`: Groth-based OTS

Configure these in `main.rs`:
```rust
let ur_proof_type = "GS";           // User registration proof type
let submission_proof_type = "GS";   // Submission proof type
let ots_scheme = OTSignatureSchemeType::P(POTSignatureScheme {});
```


## 🔗 External Resources
- [Anonize description](https://eprint.iacr.org/2015/681)
- [arkworks documentation](https://docs.rs/ark-ec/)
- [BLS12-381 specification](https://link.springer.com/chapter/10.1007/3-540-36413-7_19)
- [Groth-Sahai proofs](https://eprint.iacr.org/2007/155)
- [Structure-Preserving signature](https://eprint.iacr.org/2017/025.pdf)
- [Lamport-Diffie OTS](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/12/Constructing-Digital-Signatures-from-a-One-Way-Function.pdf)
- [Groth-based OTS](http://www0.cs.ucl.ac.uk/staff/J.Groth/NIZKGroupSignFull.pdf)

## ⚠️ Security Notice

This is a **research prototype** implementation intended for academic evaluation. It has not undergone formal security audits and should not be used in production systems without thorough review and testing.

## License

This project is licensed under either the Apache License Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE)) or theMIT License ([LICENSE-MIT](./LICENSE-MIT)).

