import base58
import hashlib
from hashlib import sha256
import base64
import binascii
import json
import os
import pprint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import time


def doubleSha256(hex):
    bin = binascii.unhexlify(hex)
    hash = hashlib.sha256(bin).digest()
    hash2 = hashlib.sha256(hash).digest()
    return hash2


def hexToBase58(key):
    payload_str = '1C'+key
    payload_unhex = binascii.unhexlify(payload_str)
    checksum = doubleSha256(payload_str)[0:4]
    return base58.b58encode(payload_unhex+checksum, base58.RIPPLE_ALPHABET)


def base58ToHex(b58_str):
    decb58 = base58.b58decode(b58_str, base58.RIPPLE_ALPHABET)
    payload_unhex = decb58[:-4]
    checksum = decb58[-4:]
    payload_hex = binascii.hexlify(payload_unhex)
    #print("payloadstr : ",payload_hex[2:])
    check = (checksum == doubleSha256(payload_hex)[0:4])
    if not check:
        print("Checksum check: ", (check))

    return payload_hex[2:]


def base58ToBytes(b58_str):
    decb58 = base58.b58decode(b58_str, base58.RIPPLE_ALPHABET)
    payload_unhex = decb58[:-4]
    checksum = decb58[-4:]
    payload_hex = binascii.hexlify(payload_unhex)
    #print("payloadstr : ",payload_hex[2:])
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
        # print(type(mtypefield))
        if type(mtypefield) == bytes:
            mtypefield = int.from_bytes(mtypefield, 'big')

        if mtypefield == 0x24:
            manifest_dec['sequence'] = int.from_bytes(data, 'big')
        elif mtypefield == 0x71:
            # binascii.hexlify(data)#hexToBase58(binascii.hexlify(data))#base58ToHex(data)#
            manifest_dec['master_public_key'] = bytesToBase58(data)
        elif mtypefield == 0x73:
            # binascii.hexlify(data)#hexToBase58(binascii.hexlify(data))#base58ToHex(data)#hexToBase58(data)
            manifest_dec['signing_public_key'] = bytesToBase58(data)
        elif mtypefield == 0x76:
            manifest_dec['signature'] = binascii.hexlify(data)
        elif mtypefield == 0x7012:
            manifest_dec['master_signature'] = binascii.hexlify(data)
        elif mtypefield == 0x77:
            manifest_dec['domain'] = data
        else:
            print("Unexpected parsed field: ",
                  mtypefield, data, manifest_bytes)

    return manifest_dec


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


def createUNL(validators_names_list: list, validator_gen_keys: dict, version: int, keys_path: str):
    """Creates a properly signed UNL that contains only the validators in the validators_names_list

    Arguments:
        validators_names_list {list} -- [description]
        master_keys {dict} -- [description]
        ephemeral_keys {dict} -- [description]
        version {int} -- [description]
        keys_path {str} -- the root path for the validators keys
    """
    munl = {}
    mblob_data = {}
    mblob_data['validators'] = createValidatorsList(
        validators_names_list, keys_path)
    mblob_data['sequence'] = version
    # We set the expiration date to be 1 year after.
    td = time.mktime(time.strptime("19710101000000", "%Y%m%d%H%M%S"))
    mblob_data['expiration'] = int(convertToRippleTime(time.time()) + td)
    
    # print(mblob_data, type(mblob_data))
    mblob_bin = base64.b64encode(json.dumps(mblob_data).encode('ascii'))
    munl['blob'] = mblob_bin.decode('ascii')

    # mSecK=Ed25519PrivateKey.from_private_bytes(base58ToBytes(validator_gen_keys['secret_key']))
    # mPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(validator_gen_keys['public_key']))
    # man_master_signature=mSecK.sign(munl['blob'])#createManifestForSigning(sequence,public_key,signing_public_key))

    # munl['signature']=mSecK.sign(munl['blob'])
    signing_public_key = decodeManifest(validator_gen_keys['manifest'])[
        'signing_public_key']
    mSignK = Ed25519PrivateKey.from_private_bytes(
        binascii.unhexlify(validator_gen_keys['validation_secret_key']))
    # base58ToBytes(binascii.unhexlify(validator_gen_keys['validation_secret_key'])))
    # mSignPubK=Ed25519PublicKey.from_public_bytes(base58ToBytes(signing_public_key))

    # man_signature=mSignK.sign(munl)#createManifestForSigning(sequence,public_key,signing_public_key))

    munl['signature'] = binascii.hexlify(
        mSignK.sign(mblob_bin)).decode('ascii')
    munl['manifest'] = validator_gen_keys['manifest']
    munl['version'] = 1
    munl['public_key'] = base58ToHex(validator_gen_keys['public_key'].decode('ascii')).upper().decode('ascii')

    # print("DEBUG: createUNL(): ", validator_gen_keys, munl)

    return munl
