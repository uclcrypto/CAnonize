# Artifact Appendix

Paper title: **CAnonize: a Compact Anonymous Survey Protocol**

Requested Badge(s):
  - [ ] **Available**
  - [ ] **Functional**
  - [x] **Reproduced**

## Description 
Rust implementation of the CAnonize protocol for anonymous surveys on the BLS12-381 curve.
This artifact allows running one survey with one participant using the CAnonize protocol or the Anonize protocol and also allows reproducing the results presented in the paper "CAnonize: a Compact Anonymous Survey Protocol".

### Security/Privacy Issues and Ethical Concerns
Nothing to report.

## Basic Requirements

### Hardware Requirements

Can run on a laptop (no special hardware requirements).

The experiments reported in the paper were performed on a machine equipped with an Intel Core i7-1355U CPU with base frequency 1GHz, turbo frequency up to 5GHz and 16 GB RAM.

### Software Requirements

The artifact was run on a machine using Ubuntu 22.04.1 but can be run on any OS.

We provide a Docker container for reproducing our results. The Docker version used is 29.4.1.

The implementation is provided in Rust (v.1.85.0). The required Rust packages are listed in the _Cargo.toml_ file under the "_dependencies_" section.



### Estimated Time and Storage Consumption 
 

The artifact can be run in less than 5 minutes if Rust is already installed.

The Github repository takes around 900 MB and Docker image takes 1.77 GB.



## Environment 

### Accessibility

The artifact is accessible here: [https://github.com/uclcrypto/CAnonize](https://github.com/uclcrypto/CAnonize).

### Set up the environment 

1. Make sure you have a working [Rust installation](https://rust-lang.org/tools/install/).
2. Clone the repository and build the project
```bash
git clone git@github.com:uclcrypto/CAnonize.git
cargo build --release
```
3. If you want to run the Docker image provided:
```bash
docker build -t canonize .
```


### Testing the Environment 

Check your installation by running the tests.
```bash
cargo test --release
```
For testing the Docker image:
```bash
docker run -it --rm --entrypoint bash canonize
cargo test --release
```

The ten unit tests should pass.

## Artifact Evaluation 


### Main Results and Claims

This Rust implementation allows:
- running the CAnonize and Anonize protocols
- measuring the communication and computational costs of each survey step for the CAnonize and Anonize protocols (Tables 2 and 4).
- measuring the execution time of the most time consuming operations and computing the theoretical communication cost and execution time (Tables 2 and 4).

The results are provided for the BLS12-381 curve.

#### Main Result 1: CAnonize and Anonize protocols implementation

This implementation allows running the CAnonize and Anonize protocols for a representative working flow involving one survey involving one registration authority, one survey authority and one user.

To ensure a fair comparison, we used same libraries and optimizations for both implementations and no batching techniques were employed that could give an advantage to CAnonize. The proposed implementation of Anonize uses a transform due to Fischlin instead of the less efficient transform due to Pass used in the Anonize paper.

#### Main Result 2: Communication and computational cost reduction

We claim that the total communication cost is reduced by 92% in CAnonize compared to Anonize. We provide the communication cost of the user registration, survey registration and submission steps for both CAnonize and Anonize protocols, to reproduce Table 2.

We claim that the total communication cost is reduced by 59% in CAnonize compared to Anonize. We provide the median execution time on 50 runs of each entity for each survey step, to reproduce Table 4.

#### Main Result 3: Operations timing and theoretical evaluation

We provide a benchmark for measuring the execution times of the main operations used in the protocols and provide a script computing the theoretical communication cost by evaluating the total size of each communicated element and the expected theoretical execution time by evaluating the total number of operations in each step and multiplying them by their execution time.

### Experiments

#### Experiment 1: CAnonize and Anonize protocols implementation
For running the CAnonize protocol:
``` bash
cargo run --release AS
```
For running the Anonize protocol:
```bash
cargo run --release AN
```
The first compilation takes around 10 s and the execution takes less than 1 s.

The expected output presents the execution time for each survey step in ms and the communication cost for each step in bits (ours for CAnonize, orig. for Anonize, RA for registration authority, SA for survey authority, UR for user registration, SR for survey registration):

| Exp. type | RA setup | SA setup | User setup | CRS generation | UR1 | UR2 | UR3 | Survey registration | Authorisation | Submission | Submission check | User total | RA total | SA total | Total (ms) |
| --------- | -------: | -------: | ---------: | -------------: | --: | --: | --: | ------------------: | ------------: | ---------: | ---------------: | ---------: | -------: | -------: | ---------: |
| ours      |       14 |        6 |          0 |             11 |   4 |  13 |  17 |                   2 |            17 |         71 |              199 |         94 |       28 |      208 |        359 |


| Exp. type |   UR1 |   UR2 | UR_tot |    SR | Submission | Total size (bits) |
| --------- | ----: | ----: | -----: | ----: | ---------: | ----------------: |
| ours      | 5,056 | 3,456 |  8,512 | 3,456 |     52,544 |            64,512 |


#### Experiment 2: Communication and computational cost reduction
The following commands shows median execution time over 50 runs of the CAnonize (ours) and Anonize (orig.) protocols for each survey step (Table 4) and shows the communication cost for each step of each protocol (Table 2). 

```bash
docker run -it --rm --entrypoint bash canonize
./bench.sh
```
Running the benchmark takes around 40 seconds.

The expected output for the execution time is:
| Exp_type | RA_setup | SA_setup | U_setup | CRS_Setup | UR_U | UR_RA |  SR | Auth |   Sub |  Sub2 |  User |   RA |    SA | Tot (ms) |
| -------- | -------: | -------: | ------: | --------: | ---: | ----: | --: | ---: | ----: | ----: | ----: | ---: | ----: | -------: |
| orig.    |     1.0 |    1.0 |   0.0 |       0.0 | 8.0 |  6.0 | 0.0 |  3.0 | 157.0 | 238.0 | 168.5 | 8.0 | 245.0 |    439.0 |
| ours     |     4.0 |    5.5 |    0.0 |       9.5 | 10.0 |   6.0 | 1.0 |  8.0 |  37.0 |  91.0 |  48.0 | 11.0 | 107.0 |    179.0 |

The expected output for the communication cost is:
| Exp. type |    UR1 |   UR2 | UR_tot |    SR | Submission | Total size (bits) |
| --------- | -----: | ----: | -----: | ----: | ---------: | ----------------: |
| ours      |  5,056 | 3,456 |  8,512 | 3,456 |     52,544 |            64,512 |
| orig.     | 59,328 | 2,688 | 62,016 | 2,688 |    563,712 |           628,416 |


#### Experiment 3: Operation timing and theoretical evaluation 

The theoretical communication size (Table 2) is obtained by computing manually the total number of exchanged group elements and multiplying them by their size on the BLS12-381 curve ($Z_q$: 255 bits, $G_1$: 381 bits, $G_2$: 762 bits, $G_T$: 4572 bits).

The theoretical execution time (Table 4) is obtained by multiplying the number of operations computed in Table 3 by a reference execution time for each operation.

```bash
docker run -it --rm --entrypoint bash canonize
cargo bench
```
The previous commands allow benchmarking the following operations over 50 runs (ms): hashing, hash-to-curve in $G_1$ and $G_2$, pairing evaluation, multiplication in $G_T$ and exponentiations in $G_1$ and $G_2$.

The theoretical communication size and execution time can be obtained using the following script.
```bash
docker run -it --rm --entrypoint bash canonize
python3 theo_size_time.py
```
The expected outputs are:
| Exp_type |     UR |    SR |    Subm | Tot (bit) |
| -------- | -----: | ----: | ------: | -------: |
| ours     |  5,334 | 2,667 |  31,752 |   39,753 |
| orig.    | 38,958 | 1,524 | 493,872 |  534,354 |

| Exp_type | Total theoretical time (ms) |
| ------ | --------------------------: |
| ours   |                         117 |
| orig.  |                         388 |


Running the benchmark for the operations timing takes around 1 min 40s. 
The theoretical communication and computational costs are computed in less than 1s.


## Limitations

Table 3 shows the number of hashing, pairing evaluations, multiplications in $G_T$, exponentiations in $G_1$ and $G_2$ for each survey step. Those numbers were computed manually.

## Notes on Reusability

It is possible to change the Groth-Sahai proof implementation by changing the value of the *ur_proof_type* and *submission_proof_type* variables in _main.rs_. _GSLIB_ can be used for using the implementation provided by the *groth-sahai* library and _Schnorr_ can be used for using the Schnorr proof. Other proof schemes can be implemented and added in the _user_registration1_, _submission_ functions of the _UserTrait_, the _user_registration_2_ function of the registration authority and the _submission_check_ function of the survey authority.

The signature scheme used can be easily replaced by implementing the _SignatureScheme_ trait, adding the scheme to the _SignatureSchemeType_ enum and replacing the _signature_scheme_ variable output by the _setup_ function. Similarly, the one-time signature scheme can be replaced by implementing the _OTSignatureScheme_ trait, adding the scheme to the _OTSignatureSchemeType_ and replacing the _ots_scheme_ variable in *main.rs*.


