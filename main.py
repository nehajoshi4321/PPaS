import random
import os
import string
import math
import petlib
from bplib import bp
import numpy
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Hash import SHA

numDom = int(input("Enter number of domains: "))
numVNF = int(input("Enter number of VNFs for each domain: "))
reqSize = int(input("Enter the number of VNFs requested by the user: "))

print("Generating VNF pool.")
vnf=[]

domain = [[] for i in range(0, numDom)]

for i in range(0, int((numDom*numVNF)/2)):
    result = ''.join((random.choice(string.ascii_lowercase) for x in range(16)))
    vnf.append(result)
    print(result)

print("Domain VNF Registeration.")
for i in range(0, numDom):
    for j in range(0, numVNF):
        v = vnf[random.randint(0, len(vnf)-1)]
        domain[i].append(v)

print(domain)

userReq = []
print("Generating User Request.")
for i in range(0, reqSize):
    userReq.append(vnf[random.randint(0, len(vnf) - 1)])
print(userReq)

domainKeys = []
print("Generating keys.")

key = ElGamal.generate(400, Random.new().read)
for i in range(0, numDom):
    domainKeys.append(key)

print("Performing intersection.")
res = ""
for i in range(0, numDom):
    for j in domain[i]:
        for k in userReq:
            _j = SHA.new(bytes(j, 'utf-8')).digest()
            os.environ['_j'] = str(_j)
            _k = SHA.new(bytes(k, 'utf-8')).digest()
            os.environ['_k'] = str(_k);
            os.system("./pairings_in_c/build/pairing_intersection _j _k > /dev/null")
            c = (int.from_bytes(_j, 'big') & int.from_bytes(_k, 'big')).to_bytes(len(_j), 'big')
            if(c == _j):
                res += ("Domain " + str(i) + " has common:  " + j + "\n")
            #if(j == k):
            #    print(j)
        #print(SHA.new(bytes(j, 'utf-8')).digest())

print(res)

#    print("Generatin")
