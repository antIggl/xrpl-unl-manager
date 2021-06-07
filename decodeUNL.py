#!/usr/bin/env python3

import argparse
import sys
import utils
import json
import requests
import base64
import binascii
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

argparser=argparse.ArgumentParser(description="Decodes an XRP Ledger UNL either from a file or from a URL")
cmdgroup=argparser.add_mutually_exclusive_group(required=True)
cmdgroup.add_argument("-f","--file", type=str, help="Defines the UNL file to be parsed")
cmdgroup.add_argument("-u","--url", type=str, help="Defines the URL to retrieve the UNL file")
# cmdgroup.set_defaults()

argparser.add_argument("-v","--validate", default=False,action="store_true",
                            help="Enables the UNL validation during the decoding")
pgroup=argparser.add_mutually_exclusive_group(required=False)
pgroup.add_argument("-praw","--print-raw", help="Prints the UNL JSON as received", action="store_true")
pgroup.add_argument("-pb","--print-blob", help="Prints the UNL blob JSON object", action="store_true")
pgroup.add_argument("-pr","--print-raw", help="Prints the UNL JSON object (RAW)", action="store_true")
pgroup.add_argument("-prb","--print-raw-blob", help="Prints the UNL blob RAW", action="store_true")
pgroup.add_argument("-pl","--print-validators-list", help="Prints the validators public keys list only", action="store_true")
pgroup.add_argument("-pv","--print-validators", help="Prints the validators objects list only", action="store_true")
pgroup.add_argument("-pm","--print-manifest", help="Prints the validators list manifest", action="store_true")
pgroup.add_argument("-ps","--print-signature", help="Prints the validators list signature", action="store_true")

argparser.add_argument("-o","--output-file", type=str,default='./decoded-list.json',help="Defines the output file.")

aa=argparser.parse_args()
#print (aa)

lfile='./encoded-list.json'
vlistcont=None
if aa.file :
    lfile=aa.file
    with open(lfile,'r') as f:
        vlistcont=json.load(f)
else:
    # should be retrieved from url
    if len(aa.url)>0:
        r = requests.get(aa.url)
        if r.status_code == requests.codes.ok :
            vlistcont=r.json()
        else:
            print("Could get a valid response from {} \n Response: {}".format(aa.url,r.status_code))
    else:
        print ("Error: no url")

if aa.print_raw:
    print(vlistcont)

valist= utils.decodeValList(vlistcont)
if aa.print_validators_list:
    print(valist)

if aa.print_raw_blob:
    print(vlistcont['blob'])

list_blob = json.loads(base64.b64decode(vlistcont['blob']))
if aa.print_blob:
    print(list_blob)

# print (list_blob['validators'])

lman=utils.decodeManifest(vlistcont['manifest'])
if aa.print_manifest :
    # print("Printing decoded manifest of the list")
    print (lman)

if aa.print_signature:
    print(vlistcont['signature'])


#TODO: verification

#print (vlistcont['public_key'], len(vlistcont['public_key']))

#print (vlistcont['signature'], len(vlistcont['signature']))

#mPubK_bytes=binascii.a2b_hex(vlistcont['public_key'])
#if mPubK_bytes[0]==0xed:
#    print("ED key")
#    mPubK=Ed25519PublicKey.from_public_bytes(mPubK_bytes[1:])
#else:
#    print ("Not a ED25519 key")
#    sys.exit(1)


# verifying
#signature_bytes=binascii.a2b_hex(vlistcont['signature'])
#verifying_data=base64.b64decode(vlistcont['blob']
#verifying_data= bytes(vlistcont['blob'],'utf8')

#mPubK.verify(signature_bytes,verifying_data)

#mSignPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(signing_public_key))

# utils.validate(vlistcont['public_key'], base64.b64decode(vlistcont['blob']), vlistcont['signature'])
import binascii
utils.validate(utils.base58ToBytes(lman['signing_public_key']), base64.b64decode(vlistcont['blob']), binascii.unhexlify(vlistcont['signature']))

# utils.validate(binascii.unhexlify(vlistcont['public_key']), base64.b64decode(vlistcont['blob']), binascii.unhexlify(vlistcont['signature']))
