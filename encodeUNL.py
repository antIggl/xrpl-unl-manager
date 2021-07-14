#!/usr/bin/env python3
import sys
import utils
import json
import os

def parseValidatorTokenFile(vtokenfname):
    """Parses the validator-token.txt file and return a json object

    Arguments:
        vtokenfname {[type]} -- [description]

    Returns:
        [type] -- [description]
    """
    with open(vtokenfname,'r') as f:
        vkcont=f.read()

    
    vtokenstr=vkcont.split('[validator_token]')[1].strip()
    
    vtokenstr=vtokenstr.replace('\n','')
    # print(vtokenstr)
    return (utils.decodeValidatorToken(vtokenstr))

def parseListFile(listfname:str):
    """Parses the list file
        The list file could be either line list of validators' names OR
        a file with a json array. starts with '['

    Arguments:
        listfname {str} -- [description]
    
    Returns:
        list of validator names
    """
    with open(listfname,'r') as f:
        fcont=f.read()
    fcont=fcont.strip()
    
    if fcont.startswith('['):
        # it's json array
        return json.loads(fcont)
    else:
        # it should be a line list
        flines=fcont.split('\n')
        for l in flines:
            if l.strip().startswith('#'):
                # it's commented out
                flines.remove(l)
        return flines

if __name__=='__main__':
    import argparse
    import time

    DEFAULT_TIMEDIFF=31528800.0 # One year

    argparser=argparse.ArgumentParser(description="Encodes a XRP Ledger UNL from a file containing either a JSON list or line-separated validator names")
    argparser.add_argument("-f","--list-file", default='./unl-list.json', type=str, help="Defines the UNL file to be parsed. It needs the validators-keys-path")
    argparser.add_argument("-blf","--bloblist-file", type=str, help="Defines the UNL blob list file to be parsed. \n - Expiration date and sequence can be set separately")
    argparser.add_argument("-bf","--blob-file", type=str, help="Defines the UNL blob file to be parsed \n - Expiration date and sequence cannot be set")
    # cmdgroup.set_defaults()

    argparser.add_argument("-v","--version", default=1,type=int,
                                help="Defines the version/sequence of the UNL.")
    argparser.add_argument("-xd","--expire-date", type=str,
                help="Sets the expiration date of the generated UNL. (format: YYYYMMDDhhmmss). Defaults to 1 year since now.")

    argparser.add_argument("-kf","--keys-file", default='./unl-generator-token.txt', type=str, help="Defines the keys-pair file used to sign the UNL")
    argparser.add_argument("-kp","--validators-keys-path", default='./configfiles/', type=str, help="Defines the root path for the validators")
    argparser.add_argument("-o","--output-file", type=str,default='./encoded-list.json',help="Defines the output file.")

    aa=argparser.parse_args()

    if not aa.keys_file:
        print("--keys-file argument is required to sign the generated UNL.")
        sys.exit(1)

    # print (aa,aa.keys_file)  
    vtoken=parseValidatorTokenFile(aa.keys_file)
    
    exp_date= time.time()+DEFAULT_TIMEDIFF
    if aa.expire_date:
        exp_date=time.mktime(time.strptime(aa.expire_date, "%Y%m%d%H%M%S"))

    vkpath=None
    mvallist=[]
    munl={}
    
    if not (aa.bloblist_file or aa.blob_file):
        print("Parsing the list file {} and looking for validators keys in {}".format(aa.list_file,aa.validators_keys_path))
        mvallist=parseListFile(aa.list_file)
        vkpath=os.path.abspath(aa.validators_keys_path)
        munl=utils.createUNL(mvallist,vtoken,aa.version,vkpath,exp_date)
    
    if aa.blob_file:

        mblobvallist={}
        with open(aa.blob_file,'r')as f:
            mblobvallist= json.load(f) 

        # print (mblobvallist)
        munl=utils.createUNL_from_blob(mblobvallist,vtoken)#,vkpath)
        # print(munl, type(munl))
        # print (json.dumps(munl))
        
    if aa.bloblist_file:

        mblobvallist={}
        with open(aa.bloblist_file,'r')as f:
            mblobvallist= json.load(f) 

        # print (mblobvallist)
        munl=utils.createUNL_from_bloblist(mblobvallist,vtoken,aa.version,exp_date)
        # print(munl, type(munl))
        # print (json.dumps(munl))
        
    

        
    with open(aa.output_file,'w') as f:
        json.dump(munl,f)

    
    print ('Finished!!!')
