#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan  2 10:32:49 2023

@author: satishthomas
"""
""" Python Implementation for paper - Fraud detection through Data Sharing 
using Privacy Preserving Record Linkage employing Digital Signature(EdDSA) 
and Minhash Techniques

This implemenation is an example for Telcom A and Telecom B transacting to 
share information. Telcom B is looking to see a Fraud Indicator 'ALICE TEST BOB
'
"""
 

from superminhash import Superminhash
import ed25519
import numpy as np
import time

t0 = time.time()
N=5 #Signture length - This can be varied
JT=1.0 # Jacquard Index Threshold - We are using 1 for exact match

""" Telecom B creates the private/public key using ED25519 implemenation 
of the Digital Signature"""


privKey, pubKey = ed25519.create_keypair()

# Funtion to caluclate jacquard index
def jaccard(list1,list2):
    intersection = len(list(set(list1).intersection(set(list2))))
    union = (len(list1) + len(list2)) - intersection
    return float(intersection) / union

# Funtion to caluclate weighted jacquard index not used in this implemenation
def weighted_jaccard(vec1,vec2):
    minfeat=[]
    maxfeat=[]
    
    for i in range(len(vec1)):
        minfeat.append(min(vec1[i],vec2[i]))

        maxfeat.append(max(vec1[i],vec2[i]))
    return sum(minfeat)/sum(maxfeat)  

# Function used by Telcom A to encode its Block of data 
def encode_message(vec1): 
     signg = [float('inf') for i in range(N)]
   
     #Telecom A hash its Block using the Superminhash algorythm
     smh=Superminhash(vec1,length=N).values
    
     
     for j in range(len(smh)):
            msg = (bytes(str(smh[j]),'utf-8'))
            
            #Telcom A create its signature by encoding using its private key
            signature = privKey.sign(msg, encoding='hex')
    
            signg[j]=signature
       
     return signg  
      
   
# Function to calculate Jacquard Index to be used by Telcom B
def check_jacquard1(vec1, vec2):
  jac=0
  for j in range(len(vec1)):  
  
       msg = bytes(str(vec2[j]),'utf-8') 
    
       #Digital Signature Verify Check to be used by Telcom B
       try:
         #pubKey.verify(vec1[i], vec2[i], encoding='hex')
         pubKey.verify(vec1[j], msg, encoding='hex')
         jac =jac + 1 
        
       except:
       
         jac1=1
       
      
  return(jac/len(vec1))

# ********** Start of Fraud Checking Process between A & B *************

# Block of Fraud data by Telcom B  
my_file = open("telecom A fraud data.txt", "r")

data = my_file.read()
   
T1 = data.split("\n")
my_file.close() 
     

# Telecom B starts encoding its block of data
telecom_a = [float('inf') for k in range(len(T1))]

for k in range(len(T1)):
    
    telecom_a[k]=encode_message(T1[k])
 

# Telcom A check for Fraud Indicator by first hashing it

T2=['ALICE TEST BOB']

signature_b=Superminhash(T2[0],length=N).values

jacquard = [float('inf') for i in range(len(T1))]

t0 = time.time()

# Process to caculate the Jacquard Index and compare against the Treshold
for z in range(len(telecom_a)):  
  
  TT1=T1[z]
 
  signature_a=telecom_a[z]
  jacquard[z]=check_jacquard1(signature_a, signature_b)
  if jacquard[z]==JT:
     
     break

elapsed=(time.time() - t0)
print (jacquard)

print ('Time to run',elapsed)

count =0 

for  d in range(len(jacquard)):

     if jacquard[d]>0.0:
         count=count+1
         
print (count)
