import pandas as pd

### timing on BLS12-381 (microsecond) ###
p=884 #pairing
e1=4.3 #exponentiation G_1
e2=7.2 #exponentiation G_2
et=0 #exponentiation G_T
m1=0 #0.572#multiplication G_1
m2=0 #1.484#multiplication G_2
mt =2.4 #multiplication G_T
h=0.567 #hash
h1=142 #hash to curve G_1
h2=689 #hash to curve G_2
mq=0#0.02 #multiplication Z_q
aq=0#0.01 #addition Z_q


# size on BLS12-381 (bit)
g1=381
g2=762
gt=4572
zq=255



    
def total_theo_time():
    ours=129*p+89*mt+108*e1+91*e2+2*h+h1+2*h2
    orig = 429*p+288*mt+1620*e1+4*e2+1088*h
    return ours, orig

def ur_theo_size():
    ours= 8*g1+3*g2
    orig = 96*zq + 36 *g1 + g2
    return ours, orig
def sr_theo_size():
    ours= 5*g1+g2
    orig= 2*g1+g2
    return ours, orig
def submission_theo_size():
    ours = 2*zq + 38*g1 + 22*g2
    orig = 96*zq + 64*g1 + 2*g2 + 97*gt
    return ours, orig
def total_theo_size():
    ours = 2*zq + 51*g1 + 26*g2
    orig = 192*zq + 102*g1 + 4*g2 + 97*gt
    return ours, orig 
    


ur,ura = ur_theo_size()
sr,sra = sr_theo_size()
s,sa = submission_theo_size()
ts,tsa = total_theo_size()
rows=[["ours", ur, sr, s, ts],["orig.", ura, sra, sa, tsa]]
header = ["Exp_type", "UR", "SR","Subm", "Tot(bit)"]
df = pd.DataFrame(rows,columns=header).round(1)
print(df)
t,ta= total_theo_time()
print("Total theoretical time (ms)")
print("ours: {:.0f} ms".format(t/1000))
print("orig.: {:.0f} ms".format(ta/1000))