
import pandas as pd
import sys

file= sys.argv[1] 
df = pd.read_csv(file)

df2=df.copy()

# UR_U = UR1 + UR3
cols = list(df2.columns)
i = cols.index("UR1")
df2["UR_U"] = df2["UR1"] + df2["UR3"]
df2=df2.drop(columns=["UR1", "UR3"])
cols = [c for c in cols if c not in ["UR1", "UR3"]]
cols.insert(i, "UR_U")
df2 = df2[cols]

df2 = df2.rename(columns={"UR2": "UR_RA"})
df2 = df2.rename(columns={"CRS": "CRS_Setup"})
# Calculate median values grouped by user_type
median_values = df2.groupby('Exp_type').median().round(1)
print(median_values)

# Format the median values to one decimal place
#median_values = median_values.map(lambda x: f"{x:.1f}")

# Print Latex table
#latex_table = median_values.to_latex(index=True, caption="Median values grouped by user_type", label="tab:median_values")

#print(latex_table)

#SIZE
file2= sys.argv[2]
with open(file2, "r") as f:
    lines = [[col.strip() for col in line.strip().split(",")] for line in f if line.strip()]
header = lines[0]
rows = [line for line in lines[1:]]
df3 = pd.DataFrame(rows, columns=header)
print(df3)


