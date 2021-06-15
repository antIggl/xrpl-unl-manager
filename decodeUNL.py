#!/usr/bin/env python3

import argparse
import sys
import utils
import json
import requests
import base64


argparser=argparse.ArgumentParser(description="Decodes an XRP Ledger UNL either from a file or from a URL")
cmdgroup=argparser.add_mutually_exclusive_group(required=True)
cmdgroup.add_argument("-f","--file", type=str, help="Defines the UNL file to be parsed")
cmdgroup.add_argument("-u","--url", type=str, help="Defines the URL to retrieve the UNL file")
# cmdgroup.set_defaults()

argparser.add_argument("-v","--verify", default=False,action="store_true",
                            help="Enables the UNL verification with manifest and blob signatures during the decoding")
pgroup=argparser.add_mutually_exclusive_group(required=False)
pgroup.add_argument("-praw","--print-raw", help="Prints the UNL JSON as received", action="store_true")
pgroup.add_argument("-pb","--print-blob", help="Prints the UNL blob JSON object", action="store_true")
pgroup.add_argument("-prb","--print-raw-blob", help="Prints the UNL blob RAW", action="store_true")
pgroup.add_argument("-pl","--print-validators-list", help="Prints the validators public keys list only", action="store_true")
pgroup.add_argument("-pv","--print-validators", help="Prints the validators objects list only", action="store_true")
pgroup.add_argument("-pm","--print-manifest", help="Prints the validators list manifest", action="store_true")
pgroup.add_argument("-ps","--print-signature", help="Prints the validators list signature", action="store_true")

argparser.add_argument("-o","--output-file", type=str,default='./decoded-list-default.json',help="Defines the output file.")
argparser.add_argument("-ro","--raw-output-file", type=str,help="Defines the raw output file, as received.")

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
    # print(json.dumps(valist)


if aa.print_raw_blob:
    print(vlistcont['blob'])

list_blob = json.loads(base64.b64decode(vlistcont['blob']))
if aa.print_blob:
    print(json.dumps(list_blob))

if aa.print_validators:
    print (list_blob['validators'])


lman=utils.decodeManifest(vlistcont['manifest'])
if aa.print_manifest :
    # print("Printing decoded manifest of the list")
    print (json.dumps(lman))

if aa.print_signature:
    print(vlistcont['signature'])


if aa.raw_output_file:
    with open(aa.raw_output_file,'w') as f:
        json.dump(vlistcont,f)

if aa.output_file:
    with open(aa.output_file,'w') as f:
        json.dump(list_blob,f)

if aa.verify:
    import binascii
    mres=False
    if utils.verifyManifest(vlistcont['manifest']) :
        print (" UNL manifest verified successfully!")
        mres=True

    if utils.verify(utils.base58ToBytes(lman['signing_public_key']), base64.b64decode(vlistcont['blob']), binascii.a2b_hex(vlistcont['signature'])) :
        print (" UNL blob verified successfully!")
        #^^^ worked
        mres|=True
    
    if mres:
        print ("UNL verified successfully!")

    #print ("verification:",utils.verifyUNL(vlistcont))


    
