
from pure25519.basic import (bytes_to_clamped_scalar,
                             bytes_to_scalar, scalar_to_bytes,
                             bytes_to_element, Base)
import hashlib, binascii

def H(m):
    return hashlib.sha512(m).digest()

def publickey(seed):
    # turn first half of SHA512(seed) into scalar, then into point
    assert len(seed) == 32
    a = bytes_to_clamped_scalar(H(seed)[:32])
    A = Base.scalarmult(a)
    return A.to_bytes()

def Hint(m):
    h = H(m)
    return int(binascii.hexlify(h[::-1]), 16)

def signature(m,sk,pk):
    assert len(sk) == 32 # seed
    assert len(pk) == 32
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + pk + m) * a
    return R_bytes + scalar_to_bytes(S)

def checkvalid(s, m, pk):
    if len(s) != 64: raise Exception("signature length is wrong")
    if len(pk) != 32: raise Exception("public-key length is wrong")
    R = bytes_to_element(s[:32])
    A = bytes_to_element(pk)
    S = bytes_to_scalar(s[32:])
    h = Hint(s[:32] + pk + m)
    v1 = Base.scalarmult(S)
    v2 = R.add(A.scalarmult(h))
    return v1==v2

# wrappers

import os

def create_signing_key():
    seed = os.urandom(32)
    return seed
def create_verifying_key(signing_key):
    return publickey(signing_key)

def sign(skbytes, msg):
    """Return just the signature, given the message and just the secret
    key."""
    if len(skbytes) != 32:
        raise ValueError("Bad signing key length %d" % len(skbytes))
    vkbytes = create_verifying_key(skbytes)
    sig = signature(msg, skbytes, vkbytes)
    return sig

def verify(vkbytes, sig, msg):
    if len(vkbytes) != 32:
        raise ValueError("Bad verifying key length %d" % len(vkbytes))
    if len(sig) != 64:
        raise ValueError("Bad signature length %d" % len(sig))
    rc = checkvalid(sig, msg, vkbytes)
    if not rc:
        raise ValueError("rc != 0", rc)
    return True
  
  # **************************  NEW  **************************

def inv2(x):
  return pow(x, L-2, L)

def signature2(m,sk):
    assert len(sk) == 32 # seed
#    assert len(pk) == 32
    h = H(sk[:32])
    a_bytes, inter = h[:32], h[32:]
    a = bytes_to_clamped_scalar(a_bytes)
    r = Hint(inter + m)
    R = Base.scalarmult(r)
    R_bytes = R.to_bytes()
    S = r + Hint(R_bytes + m) * a
    return R_bytes + scalar_to_bytes(S)


def extractpk(s,m):
  if len(s) != 64: raise Exception("signature length is wrong")
  R = bytes_to_element(s[:32])
  S = bytes_to_scalar(s[32:])
  h = Hint(s[:32] + m)
  h_inv = inv2(h)
#  R_neg = R.negate()
  R_neg = R.scalarmult(L-1)
  v1 = Base.scalarmult(S)
#  v2 = v1.add(R_neg)#
  v2 = v1.add(R_neg)
  A = v2.scalarmult(h_inv)
  return A

def checkpk(pk,ext_pk):
  if len(pk) != 32: raise Exception("public-key length is wrong")
  A = bytes_to_element(pk)
  if A != ext_pk:
    raise Exception("wrong public key extracted")

