#!/usr/bin/env bash
RUNS=50
OUT="bench.csv"
OUT2="size.txt"

# TIME
echo "Exp_type,RA_setup,SA_setup,U_setup,CRS,UR1,UR2,UR3,SR,Auth,Sub,Sub2,User,RA,SA,Tot(ms)" > "$OUT"

cargo build --release

USER="AS"
for ((i=1; i<=RUNS; i++)); do
    cargo run --release AS true false false >> "$OUT"
done
USER="AN"
for ((i=1; i<=RUNS; i++)); do
    cargo run --release AN true false false >> "$OUT"
done

# SIZE
echo "Exp_type,UR1,UR2,UR_tot,SR,Submission,Tot(bits)" > "$OUT2"
cargo run --release AS false true false >> "$OUT2"
cargo run --release AN false true false >> "$OUT2"

python3 bench.py "$OUT" "$OUT2"
