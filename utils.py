import base58
import hashlib
from hashlib import sha256, sha512
import base64
import binascii
import json
import os
import pprint
import cryptography

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

from ecpy.curves import Curve
from ecpy.ecdsa import ECDSA
from ecpy.keys import ECPrivateKey, ECPublicKey
_CURVE=Curve.get_curve("secp256k1")
_SIGNER=ECDSA("DER")


import time

def sha512_first_half(message: bytes) -> bytes:
    """
    Returns the first 32 bytes of SHA-512 hash of message.
    Args:
        message: Bytes input to hash.
    Returns:
        The first 32 bytes of SHA-512 hash of message.
    """
    return sha512(message).digest()[:32]

def doubleSha256(hex):
    bin = binascii.unhexlify(hex)
    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()
    return hash2


def hexToBase58(key):
    payload_str = '1C'+key
    payload_unhex = binascii.unhexlify(payload_str)
    checksum = doubleSha256(payload_str)[0:4]
    return base58.b58encode(payload_unhex+checksum, base58.XRP_ALPHABET)


def base58ToHex(b58_str):
    decb58 = base58.b58decode(b58_str, base58.XRP_ALPHABET)
    payload_unhex = decb58[:-4]
    checksum = decb58[-4:]
    payload_hex = binascii.hexlify(payload_unhex)
    #print("payloadstr : ",payload_hex[2:])
    check = (checksum == doubleSha256(payload_hex)[0:4])
    if not check:
        print("Checksum check: ", (check))

    return payload_hex[2:]


def base58ToBytes(b58_str):
    decb58 = base58.b58decode(b58_str, base58.XRP_ALPHABET)
    payload_unhex = decb58[:-4]
    checksum = decb58[-4:]
    payload_hex = binascii.hexlify(payload_unhex)
    check = (checksum == doubleSha256(payload_hex)[0:4])
    if not check:
        print("Checksum check: ", (check))

    return payload_unhex[1:]


def bytesToBase58(b58_bytes):
    return hexToBase58(b58_bytes.hex())


def decodeValList(json_list):
    vl = json.loads(base64.b64decode(json_list['blob']))['validators']
    mlist = []
    for v in vl:
        mval = hexToBase58(v['validation_public_key'])
        mlist.append(mval)
    return mlist


def decodeNextField(barray):
    if len(barray) < 2:
        return None

    cbyteindex = 0
    cbyte = barray[cbyteindex]
    ctype = ((cbyte & 0xf0) >> 4)
    cfieldid = (cbyte & 0x0f)
    typefield = cbyte

    if (ctype == 0x7):
        # blob
        if cfieldid == 0:
            # larger field id
            cbyteindex += 1
            # int.from_bytes(manifest_bytes[cbyteindex],'big')
            cfieldid = barray[cbyteindex]
            typefield = barray[:2]

        cbyteindex += 1
        cfieldlen = barray[cbyteindex]
        cbyteindex += 1
        return (typefield, barray[cbyteindex:(cbyteindex+cfieldlen)], barray[(cbyteindex+cfieldlen):])
    elif (ctype == 0x2):
        # int32
        cfieldlen = 4
    elif (ctype == 0xf):
        # int8
        cfieldlen = 1
    elif (ctype == 0x1):
        # int16
        cfieldlen = 2
    elif (ctype == 0x03):
        # int64
        cfieldlen = 8
    else:
        print("WARN: Unparsed field type")
        cfieldlen = 1
    cbyteindex += 1
    return (typefield, barray[cbyteindex:(cbyteindex+cfieldlen)], barray[(cbyteindex+cfieldlen):])


def decodeManifest(manifest_blob):
    manifest_dec = {}
    manifest_bytes = base64.b64decode(manifest_blob)

    while len(manifest_bytes) > 0:
        mtypefield, data, manifest_bytes = decodeNextField(manifest_bytes)
        if type(mtypefield) == bytes:
            mtypefield = int.from_bytes(mtypefield, 'big')

        if mtypefield == 0x24:
            manifest_dec['sequence'] = int.from_bytes(data, 'big')
        elif mtypefield == 0x71:
            manifest_dec['master_public_key'] = bytesToBase58(data)
        elif mtypefield == 0x73:
            manifest_dec['signing_public_key'] = bytesToBase58(data)
        elif mtypefield == 0x76:
            manifest_dec['signature'] = binascii.b2a_hex(data)#.hexlify(data)#data.hex()#
        elif mtypefield == 0x7012:
            manifest_dec['master_signature'] = binascii.b2a_hex(data)#.hexlify(data) #data.hex() #
        elif mtypefield == 0x77:
            manifest_dec['domain'] = data #.hex() #binascii.b2a_hex(data)
        else:
            print("Unexpected parsed field: ",
                  mtypefield, data, manifest_bytes)

    return manifest_dec

def encodeManifest(manifest_dict:dict):
    """Encodes the manifest field.
    Returns: The base64 encoded serialized manifest
    Args:
        manifest_dict (dict): dictionary having the following keys :
            * sequence : the sequence field of the manifest
            * master_public_key: The master public key of the node
            * signing_public_key: the signing public key of the node
            * domain (optional): the domain
            * signature: the signature of the serialized manifest data using signing private key
            * master_signature: the signature of the serialized manifest data using the master private key 
    """
    '''    
    Manifest Serialization:
    ManifestData are calculated as below:
    ManifestData = a bytearray properly serialized with ripple library.
    A quick and dirty way to encode and retrieve data from manifest field:
      Sequence            (type:uint32, fieldID:4)              : 0x24 | uint32_t seq
      Master public key   (type:blob, fieldID:1)                : 0x71 | uint8_t len | bytearray[len]
      Signing Public key  (type:blob, fieldID:3)                : 0x73 | uint8_t len | bytearray[len] 
      Signature           (type:blob, fieldID:6)                : 0x76 | uint8_t len | bytearray[len]
      MasterSignature     (type:blob, fieldID:18 (extra byte))  : 0x7012 | uint8_t len | bytearray[len]
      Domain              (type:blob, fieldID:7)                : 0x77 | unit8_t(len) | bytearray[len]                  
    PubKeyBytes= base58ToBytes(hexToBase58(pub_key))

    URLs:
    *https://github.com/ripple/rippled/blob/1.5.0/src/ripple/app/misc/Manifest.h
  
    * https://xrpl.org/serialization.html#field-codes
    * https://github.com/ripple/ripple-binary-codec/blob/master/src/enums/definitions.json

    * https://github.com/ripple/rippled/blob/72e6005f562a8f0818bc94803d222ac9345e1e40/src/ripple/protocol/impl/SField.cpp#L72-L266

    * https://github.com/seelabs/rippled/blob/cecc0ad75849a1d50cc573188ad301ca65519a5b/src/ripple/protocol/impl/Serializer.cpp#L484-L509
    * https://github.com/seelabs/rippled/blob/cecc0ad75849a1d50cc573188ad301ca65519a5b/src/ripple/protocol/impl/Serializer.cpp#L117-L148
    '''
    manifestPrefix=b'MAN\0'
    serializedManifest=''

    seqbytes=int.to_bytes(0x24,1,'big') + int.to_bytes(int(manifest_dict['sequence']),4,'big')
    if len(manifest_dict['master_public_key'])>=64 :
        # it's in hex bytes
        pkbytes=base58ToBytes(hexToBase58(manifest_dict['master_public_key']))
    elif len(manifest_dict['master_public_key'])!=33 :
        pkbytes=base58ToBytes(manifest_dict['master_public_key'])
    else:
        # it's in bytes (33 byte length)
        pkbytes=manifest_dict['master_public_key']

    mpkbytes=int.to_bytes(0x71,1,'big')+ int.to_bytes(len(pkbytes),1,'big')+pkbytes

    if len(manifest_dict['signing_public_key'])>=64 :
        # it's in hex bytes
        spkbytes=base58ToBytes(hexToBase58(manifest_dict['signing_public_key']))
    elif len(manifest_dict['signing_public_key'])!=33 :
        spkbytes=base58ToBytes(manifest_dict['signing_public_key'])
    else:
        # it's in bytes (33 byte length)
        spkbytes=manifest_dict['signing_public_key']

    signpkbytes=int.to_bytes(0x73,1,'big')+ int.to_bytes(len(spkbytes),1,'big')+spkbytes
    
    domainbytes=b''
    if 'domain' in manifest_dict.keys():
        dbytes=manifest_dict['domain']#.encode('ascii')
        domainbytes=int.to_bytes(0x77,1,'big')+ int.to_bytes(len(dbytes),1,'big')+dbytes
    
    msignaturebytes=int.to_bytes(0x7012,2,'big')+ int.to_bytes(len(manifest_dict['master_signature']),1,'big')+binascii.a2b_hex(manifest_dict['master_signature'])

    signaturebytes=int.to_bytes(0x76,1,'big')+ int.to_bytes(len(manifest_dict['signature']),1,'big')+binascii.a2b_hex(manifest_dict['signature'])

    
    # order: Seq, MPUBKEY,SPUBKEY,SIGNATURE,DOMAIN,MASTER_SIGNATURE
    serializedManifest=seqbytes+mpkbytes +signpkbytes+signaturebytes+domainbytes+msignaturebytes#

    return base64.b64encode(serializedManifest)

def serializeManifestData(manifest_dict:dict):
    """serializes manifest data only
        sequence, master public key, signing public key and domain
    Args:
        manifest_dict (dict): [description]
    """
    serializedManifest=''

    seqbytes=int.to_bytes(0x24,1,'big') + int.to_bytes(int(manifest_dict['sequence']),4,'big')
    if len(manifest_dict['master_public_key'])>=64 :
        # it's in hex bytes
        pkbytes=base58ToBytes(hexToBase58(manifest_dict['master_public_key']))
    elif len(manifest_dict['master_public_key'])!=33 :
        pkbytes=base58ToBytes(manifest_dict['master_public_key'])
    else:
        # it's in bytes (33 byte length)
        pkbytes=manifest_dict['master_public_key']

    mpkbytes=int.to_bytes(0x71,1,'big')+ int.to_bytes(len(pkbytes),1,'big')+pkbytes

    if len(manifest_dict['signing_public_key'])>=64 :
        # it's in hex bytes
        spkbytes=base58ToBytes(hexToBase58(manifest_dict['signing_public_key']))
    elif len(manifest_dict['signing_public_key'])!=33 :
        spkbytes=base58ToBytes(manifest_dict['signing_public_key'])
    else:
        # it's in bytes (33 byte length)
        spkbytes=manifest_dict['signing_public_key']

    signpkbytes=int.to_bytes(0x73,1,'big')+ int.to_bytes(len(spkbytes),1,'big')+spkbytes
    
    domainbytes=b''
    if 'domain' in manifest_dict.keys():
        # print(manifest_dict['domain'])
        dbytes=manifest_dict['domain']#.encode('ascii') #binascii.a2b_hex()
        domainbytes=int.to_bytes(0x77,1,'big')+ int.to_bytes(len(dbytes),1,'big')+dbytes
    
    serializedManifest=seqbytes+mpkbytes+signpkbytes+domainbytes
    # print(len(serializedManifest))
    
    return serializedManifest

def verifyManifest(manifest_blob):
    """Verifies the manifest blob using the public keys and the signatures

    Args:
        manifest_blob ([type]): the blob of the manifest

    Returns:
        True : when validated both signatures
        False: when not validated with either signature
    """
    manf_obj=decodeManifest(manifest_blob)
    serdata=serializeManifestData(manf_obj)

    mpubkeybytes= base58ToBytes(manf_obj['master_public_key'])
    # print(mpubkeybytes, mpubkeybytes[:1], len(mpubkeybytes))
    if mpubkeybytes[:1]==b'\xed' :
        # it's ED25519 key
        mpubkey=Ed25519PublicKey.from_public_bytes(mpubkeybytes[1:])
        try:
            mpubkey.verify(signature=binascii.unhexlify(manf_obj['master_signature']),data='MAN\0'.encode('ascii')+serdata)
        except InvalidSignature:
            print("Unabled to verify!")
            return False
    else:
        # print ("IT'S a ECDSA key")
        pubkey_point = _CURVE.decode_point(mpubkeybytes)
        mpubkey=ECPublicKey(pubkey_point)
        res=_SIGNER.verify('MAN\0'.encode('ascii')+serdata,binascii.unhexlify(manf_obj['master_signature']),mpubkey) #sha512_first_half('MAN\0'.encode('ascii')+serdata)
        if not res:
            print("Failed to verify",res)
            return False

    spubkeybytes= base58ToBytes(manf_obj['signing_public_key'])
    if spubkeybytes[:1]==b'\xed' :
        # it's ED25519 key
        spubkey=Ed25519PublicKey.from_public_bytes(spubkeybytes[1:])
        try:
            spubkey.verify(signature=binascii.unhexlify(manf_obj['signature']),data='MAN\0'.encode('ascii')+serdata)
        except InvalidSignature:
            print("Unabled to verify!")
            return False
    else:
        # print ("IT'S a ECDSA key")
        pubkey_point = _CURVE.decode_point(spubkeybytes)
        spubkey=ECPublicKey(pubkey_point)
        res=_SIGNER.verify(sha512_first_half('MAN\0'.encode('ascii')+serdata),binascii.unhexlify(manf_obj['signature']),spubkey)
        if not res:
            print("Failed to verify",res)
            return False


    return True
    

def signManifest(manifest_dict:dict, master_private_key, signing_private_key):
    """[summary]

    returns the manifest dictionary with updated master_signature and signature fields
    Args:
        manifest_dict (dict): [description]
        master_private_key ([type]): [description]
        signing_private_key ([type]): [description]
    """

    serdata='MAN\0'.encode('ascii')+serializeManifestData(manifest_dict)

    mpubkeybytes= base58ToBytes(manifest_dict['master_public_key'])
    if mpubkeybytes[:1]==b'\xed' :
        # it's ED25519 key
        if type(master_private_key, ec.EllipticCurvePrivateKey ):
            print("master private key type is not the same as master public key")
        if type(master_private_key, Ed25519PrivateKey):
            manifest_dict['master_signature']=binascii.hexlify(master_private_key.sign(data=serdata))
        mpubkey=Ed25519PublicKey.from_public_bytes(mpubkeybytes)
        mpubkey.verify(signature=binascii.unhexlify(manifest_dict['master_signature']),data=serdata)
    else:
        if type(master_private_key, ec.EllipticCurvePrivateKey ):
            # print ("IT'S a ECDSA key")
            manifest_dict['master_signature']=binascii.hexlify(_SIGNER.sign_rfc6979(serdata,master_private_key,sha256,canonical=True))

        if type(master_private_key, Ed25519PrivateKey ):
            print("master private key type is not the same as master public key")

        pubkey_point = _CURVE.decode_point(mpubkeybytes)
        mpubkey=ECPublicKey(pubkey_point)
        res=_SIGNER.verify(sha512_first_half(serdata),manifest_dict['master_signature'],mpubkey)
        if not res:
            print("Failed to verify")
            

    
    spubkeybytes= base58ToBytes(manifest_dict['signing_public_key'])
    if spubkeybytes[:1]==b'\xed' :
        # it's ED25519 key
        if type(signing_private_key, ec.EllipticCurvePrivateKey ):
            print("master private key type is not the same as master public key")
        if type(signing_private_key, Ed25519PrivateKey):
            manifest_dict['signature']=binascii.hexlify(signing_private_key.sign(data=serdata))
        spubkey=Ed25519PublicKey.from_public_bytes(spubkeybytes)
        spubkey.verify(signature=binascii.unhexlify(manifest_dict['signature']),data=serdata)
    else:
        if type(signing_private_key, ec.EllipticCurvePrivateKey ):
            manifest_dict['signature']=binascii.hexlify(_SIGNER.sign_rfc6979(serdata,signing_private_key,sha256,canonical=True))
            # print ("IT'S a ECDSA key")

        if type(signing_private_key, Ed25519PrivateKey):
            print("signing private key type is not the same as signing public key")

        pubkey_point = _CURVE.decode_point(spubkeybytes)
        spubkey=ECPublicKey(pubkey_point)
        res=_SIGNER.verify(sha512_first_half(serdata),manifest_dict['signature'],spubkey)
        if not res:
            print("Failed to verify")
            
    return manifest_dict
    

def decodeValidatorToken(validator_token: str):
    """Decodes validator token and returns a JSON object with manifest, public keys and validation_secret_key

    Arguments:
        validator_token {str} -- [description]
    """
    vtokenObj = json.loads(base64.b64decode(validator_token))
    # print (vtokenObj)
    vkeys = vtokenObj
    manif = decodeManifest(vtokenObj['manifest'])
    vkeys['public_key'] = manif['master_public_key']
    vkeys['signing_public_key']=manif['signing_public_key']
    return vkeys


def createValidatorsList(validators_names_list: list, keys_path: str):
    """Gets a list of validators names and returns a list of validators public keys and manifests.

    Arguments:
        validators_names_list {list} -- [description]
        keys_path {str} -- [description]
    """
    vallist = []
    for valname in validators_names_list:
        mval = {}
        valkeys_fname = keys_path+'/'+valname+'/validator-keys.json'
        if os.path.exists(valkeys_fname):
            with open(valkeys_fname, 'r') as f:
                mvalkeys = json.load(f)
            mval['validation_public_key'] = base58ToHex(
                mvalkeys['public_key']).upper().decode('ascii')
            mval['manifest'] = base64.b64encode(
                binascii.unhexlify(mvalkeys['manifest'])).decode('ascii')
            vallist.append(mval)
        else:
            continue
    return vallist


def convertToRippleTime(tstamp=time.time()):
    """Converts given timestamp, seconds since Epoch(1/1/1970), to Ripple Timestamp, seconds since Ripple Epoch (1/1/2000)

    Args:
        tstamp (timestamp, optional): The timestamp (seconds from Epoch). Defaults to time.time().

    Returns:
        timestamp: Ripple Timestamp, seconds since Ripple Epoch (1/1/2000)
    """
    ripple_epoch = time.mktime(time.strptime("20000101000000", "%Y%m%d%H%M%S"))
    return tstamp - ripple_epoch

def convertToUnixTime(rtstamp):
    """Converts given timestamp, seconds since Epoch(1/1/1970), to Ripple Timestamp, seconds since Ripple Epoch (1/1/2000)

    Args:
        tstamp (timestamp, optional): The timestamp (seconds from Epoch). Defaults to time.time().

    Returns:
        timestamp: Ripple Timestamp, seconds since Ripple Epoch (1/1/2000)
    """
    ripple_epoch = time.mktime(time.strptime("20000101000000", "%Y%m%d%H%M%S"))
    return rtstamp + ripple_epoch




def createUNL_from_blob(blob_dict,validator_gen_keys:dict):
    """
    Creates a properly signed UNL with the blob_dict.
    """
    munl = {}

    munl['public_key'] = base58ToHex(validator_gen_keys['public_key'].decode('ascii')).upper().decode('ascii')
    munl['manifest'] = validator_gen_keys['manifest']

    mblob_bytes = json.dumps(blob_dict)
    mblob_bin = base64.b64encode(mblob_bytes.encode('ascii'))
    munl['blob']=mblob_bin.decode('ascii')

    signing_public_key = decodeManifest(validator_gen_keys['manifest'])[
        'signing_public_key']
    
    is_ed25519=(signing_public_key[0]==0xed)
    if is_ed25519:
        # print ("IT'S ED25519 key")
        mSignK = Ed25519PrivateKey.from_private_bytes( binascii.unhexlify(validator_gen_keys['validation_secret_key']))
        mSignPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(signing_public_key)[1:])
        munl['signature'] = mSignK.sign(mblob_bytes.encode('ascii')).hex().upper()
    else:
        # print ("IT'S a ECDSA key")
        ### Important info:
        # line:987 https://github.com/ripple/rippled/blob/develop/src/ripple/app/misc/impl/ValidatorList.cpp
        # The hashing algorithm for the fullhash is sha512half --> SHA512_256()<--- WRONG!!! it's first half of SHA512
        #############
        # use ECPY
        mSignK = ECPrivateKey(int(validator_gen_keys['validation_secret_key'],16),_CURVE)
        pubkey_point=_CURVE.decode_point(base58ToBytes(signing_public_key))
        mSignPubK=ECPublicKey(pubkey_point)
        munl['signature'] = _SIGNER.sign_rfc6979(sha512_first_half(mblob_bytes.encode('ascii')),mSignK,sha256,canonical=True).hex().upper()
        

    # print( "\nmblob bytes: ",mblob_bytes, type(mblob_bytes.encode('ascii')))
    # print("\nvalidator gen keys:",validator_gen_keys)
    # print("\n manifest: ", decodeManifest(validator_gen_keys['manifest']))
    
    #print("unl signature: ", munl['signature'], len(munl['signature']))

    # munl['manifest'] = validator_gen_keys['manifest']
    munl['version'] = 1
    # munl['public_key'] = base58ToHex(validator_gen_keys['public_key'].decode('ascii')).upper().decode('ascii')

    # print("\nDEBUG: createUNL(): ", validator_gen_keys, munl)

    return munl

def createUNL_from_bloblist(bloblist: list, validator_gen_keys: dict, version: int,expiration_date:float=None):
    """
    Creates a properly signed UNL using the bloblist for "validators" key in blob. 
    It sets the version/sequence of the UNL and the expiration date.

    """
    munl = {}
    mblob_data = {}

    munl['public_key'] = base58ToHex(validator_gen_keys['public_key'].decode('ascii')).upper().decode('ascii')
    munl['manifest'] = validator_gen_keys['manifest']

    mblob_data['sequence'] = version
    if expiration_date==None:
        # We set the expiration date to be 1 year after.
        td = time.mktime(time.strptime("19710101000000", "%Y%m%d%H%M%S"))
        mblob_data['expiration'] = int(convertToRippleTime(time.time()) + td)
    else:
        mblob_data['expiration'] = int(convertToRippleTime(expiration_date))

    mblob_data['validators'] = bloblist
    # print(mblob_data, type(mblob_data))
    mblob_bytes=json.dumps(mblob_data)
    
    mblob_bin = base64.b64encode(mblob_bytes.encode('ascii'))
    munl['blob'] = mblob_bin.decode('ascii')

    signing_public_key = decodeManifest(validator_gen_keys['manifest'])['signing_public_key']
    is_ed25519=(signing_public_key[0]==0xed)
    if is_ed25519:
        # print ("IT'S ED25519 key")
        mSignK = Ed25519PrivateKey.from_private_bytes( binascii.unhexlify(validator_gen_keys['validation_secret_key']))
        mSignPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(signing_public_key)[1:])
        
        munl['signature'] = mSignK.sign(mblob_bytes.encode('ascii')).hex().upper()
    else:
        # print ("IT'S a ECDSA key")
        ### Important info:
        # line:987 https://github.com/ripple/rippled/blob/develop/src/ripple/app/misc/impl/ValidatorList.cpp
        # The hashing algorithm for the fullhash is sha512half --> SHA512_256()<--WRONG, It's first half of SHA512
                
        # using ECPY 
        mSignK = ECPrivateKey(int(validator_gen_keys['validation_secret_key'],16),_CURVE)
        pubkey_point=_CURVE.decode_point(base58ToBytes(signing_public_key))
        mSignPubK=ECPublicKey(pubkey_point)
        munl['signature'] = _SIGNER.sign_rfc6979(sha512_first_half(mblob_bytes.encode('ascii')),mSignK,sha256,canonical=True).hex().upper()
        
    # print( "\nmblob bytes: ",mblob_bytes, type(mblob_bytes.encode('ascii')))
    # print("\nvalidator gen keys:",validator_gen_keys)
    # print("\n manifest: ", decodeManifest(validator_gen_keys['manifest']))
    
    #print("unl signature: ", munl['signature'], len(munl['signature']))

    
    munl['version'] = 1
   

    # print("\nDEBUG: createUNL(): ", validator_gen_keys, munl)

    return munl

    

def createUNL(validators_names_list: list, validator_gen_keys: dict, version: int, keys_path: str,expiration_date:float=None):
    """Creates a properly signed UNL that contains only the validators in the validators_names_list

    Arguments:
        validators_names_list {list} -- [description]
        master_keys {dict} -- [description]
        ephemeral_keys {dict} -- [description]
        version {int} -- [description]
        keys_path {str} -- the root path for the validators keys
        expiration_date {float} -- expiration date in seconds since unix epoch
    """
    munl = {}
    mblob_data = {}
    
    # keys sequence on vl.ripple.com
    # public_key, manifest, blob, signature, version

    
    munl['public_key'] = base58ToHex(validator_gen_keys['public_key'].decode('ascii')).upper().decode('ascii')
    munl['manifest'] = validator_gen_keys['manifest']
    
    mblob_data['sequence'] = version
    if expiration_date==None:
        # We set the expiration date to be 1 year after.
        td = time.mktime(time.strptime("19710101000000", "%Y%m%d%H%M%S"))
        mblob_data['expiration'] = int(convertToRippleTime(time.time()) + td)
    else:
        mblob_data['expiration'] = int(convertToRippleTime(expiration_date))

    mblob_data['validators'] = createValidatorsList(
        validators_names_list, keys_path)

    mblob_bytes=json.dumps(mblob_data)
    
    mblob_bin = base64.b64encode(mblob_bytes.encode('ascii'))
    munl['blob'] = mblob_bin.decode('ascii')

    signing_public_key = decodeManifest(validator_gen_keys['manifest'])[
        'signing_public_key']
    
    is_ed25519=(signing_public_key[0]==0xed)
    if is_ed25519:
        print ("IT'S ED25519 key")
        mSignK = Ed25519PrivateKey.from_private_bytes( binascii.unhexlify(validator_gen_keys['validation_secret_key']))
        mSignPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(signing_public_key)[1:])
        
        munl['signature'] = mSignK.sign(mblob_bytes.encode('ascii')).hex().upper()
    else:
        # print ("IT'S a ECDSA key")
        ### Important info:
        # line:987 https://github.com/ripple/rippled/blob/develop/src/ripple/app/misc/impl/ValidatorList.cpp
        # The hashing algorithm for the fullhash is sha512half --> SHA512_256() <-- WRONG, it's first half of SHA512
        #############
        
        # using ECPY 
        mSignK = ECPrivateKey(int(validator_gen_keys['validation_secret_key'],16),_CURVE)
        pubkey_point=_CURVE.decode_point(base58ToBytes(signing_public_key))
        mSignPubK=ECPublicKey(pubkey_point)
        munl['signature'] = _SIGNER.sign_rfc6979(sha512_first_half(mblob_bytes.encode('ascii')),mSignK,sha256,canonical=True).hex().upper()
        
      
    # print( "\nmblob bytes: ",mblob_bytes, type(mblob_bytes.encode('ascii')))
    # print("\nvalidator gen keys:",validator_gen_keys)
    # print("\n manifest: ", decodeManifest(validator_gen_keys['manifest']))
    
    #print("unl signature: ", munl['signature'], len(munl['signature']))

    munl['version'] = 1
    
    # print("\nDEBUG: createUNL(): ", validator_gen_keys, munl)

    return munl


def verifyUNL(unl):
    """
    Verifies the UNL against the signing public key and the signatures for both blob and manifest.
    """
    lman=decodeManifest(unl['manifest'])
    mres=False
    mres=verifyManifest(unl['manifest'])
    mres&=verify(base58ToBytes(lman['signing_public_key']), base64.b64decode(unl['blob']), binascii.a2b_hex(unl['signature']))
    
    list_blob = json.loads(base64.b64decode(unl['blob']))
    for v in list_blob['validators']:
        vman=decodeManifest(v['manifest'])
        # print("Serialized: ",utils.encodeManifest(vman))
        # print("Original:     ", v['manifest'])#base64.b64decode(v['manifest']))
        vv=verifyManifest(v['manifest'])
        mres&=vv
        # print (vman['master_public_key'], vv)

    return mres




def verify(public_key, binary, signature):
    """[summary]

    Args:
        public_key ([type]): [description]
        binary ([type]): [description]
        signature ([type]): [description]
    """
    # print(binascii.hexlify(public_key))
    is_ed25519=(public_key[0]==0xed)

    if is_ed25519:
        # print ("It's ED25519 key")
        pk=Ed25519PublicKey.from_public_bytes(public_key[1:])
        
        try:
            pk.verify(signature,data=binary)
        except InvalidSignature :
            print("Cannot be validated")
            return False
        return True
    else:
        pubkey_point=_CURVE.decode_point(public_key)#base58ToBytes(public_key))
        # See https://xrpl.org/cryptographic-keys.html#key-derivation
        mpubkey=ECPublicKey(pubkey_point)
        a=_SIGNER.verify(sha512_first_half(binary),signature,mpubkey)
        return a
