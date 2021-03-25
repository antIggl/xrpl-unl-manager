#!/usr/bin/env python3

import argparse
import sys
import utils
import json
import urllib.request as ureq
import base64

argparser=argparse.ArgumentParser(description="Decodes an XRP Ledger UNL either from a file or from a URL")
cmdgroup=argparser.add_mutually_exclusive_group(required=True)
cmdgroup.add_argument("-f","--file", type=str, help="Defines the UNL file to be parsed")
cmdgroup.add_argument("-u","--url", type=str, help="Defines the URL to retrieve the UNL file")
# cmdgroup.set_defaults()

argparser.add_argument("-v","--validate", default=False,action="store_true",
                            help="Enables the UNL validation during the decoding")
pgroup=argparser.add_mutually_exclusive_group(required=False)
pgroup.add_argument("-pb","--print-blob", help="Prints the UNL blob JSON object", action="store_true")
pgroup.add_argument("-pl","--print-validators-list", help="Prints the validators public keys list only", action="store_true")
pgroup.add_argument("-pv","--print-validators", help="Prints the validators objects list only", action="store_true")
argparser.add_argument("-o","--output-file", type=str,default='./decoded-list.json',help="Defines the output file.")

aa=argparser.parse_args()
print (aa)

lfile='./encoded-list.json'
vlistcont=None
if aa.file :
    lfile=aa.file
    with open(lfile,'r') as f:
        vlistcont=json.load(f)
else:
    # should be retrieved from url
    if len(aa.url)>0:
        with ureq.urlopen(aa.url) as r:
            vlistcont=json.load(r)
    else:
        print ("Error: no url")

print(vlistcont)

valist= utils.decodeValList(vlistcont)

print(valist)

list_blob = json.loads(base64.b64decode(vlistcont['blob']))

print(list_blob)

print (list_blob['validators'])

#TODO: verification
