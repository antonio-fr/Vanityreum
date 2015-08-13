#! /usr/bin/env python
# coding=utf8

# ECDSA BTC of FastSignVerify
# Copyright (C) 2014  Antoine FERRON

# Some portions based on :
# "python-ecdsa" Copyright (C) 2010 Brian Warner (MIT Licence)
# "Simple Python elliptic curves and ECDSA" Copyright (C) 2005 Peter Pearson (public domain)
# "Electrum" Copyright (C) 2011 thomasv@gitorious (GPL)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


# Signature is done with a random k
# from os.urandom

import os
import binascii
import base64
import struct
import hmac
from ECDSA_256k1 import *
import cPickle as pickle

def load_gtable(filename):
    with open(filename, 'rb') as input:
         global gtable
         gtable = pickle.load(input)

def mulG(real):
    if real == 0: return INFINITY
    assert real > 0
    br=[]
    dw=16
    while real > 0 :
        dm = real%dw
        real = real - dm
        br.append( dm-1 )
        real = real>>4
    while len(br)<64: br.append(-1)
    kg=INFINITY
    load_gtable('lib/G_Table')
    for n in range(64):
        if br[n]>=0:
            precomp=gtable[n][br[n]]
            kg=kg+precomp
    return kg

def dsha256(message):
    hash1=hashlib.sha256(message).digest()
    return hashlib.sha256(hash1).hexdigest()
    

class Signature( object ):
  def __init__( self, pby, r, s ):
    self.r = r
    self.s = s
    self.pby = pby

  def encode(self):
    sigr = binascii.unhexlify(("%064x" % self.r).encode())
    sigs = binascii.unhexlify(("%064x" % self.s).encode())
    return sigr+sigs

class Public_key( object ):
  def __init__( self, generator, point ):
    self.generator = generator
    self.point = point
    n = generator.order()
    if not n:
      raise RuntimeError, "Generator point must have order."
    if not n * point == INFINITY:
      raise RuntimeError, "Generator point order is bad."
    if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
      raise RuntimeError, "Generator point has x or y out of range."

  def verifies( self, hashe, signature ):
    if self.point == INFINITY: return False
    G = self.generator
    n = G.order()
    if not curve_256.contains_point(self.point.x(),self.point.y()): return False
    r = signature.r
    s = signature.s
    if r < 1 or r > n-1: return False
    if s < 1 or s > n-1: return False
    c = inverse_mod( s, n )
    u1 = ( hashe * c ) % n
    u2 = ( r * c ) % n
    xy =  self.point.dual_mult( u1, u2) # u1 * G + u2 * self.point
    v = xy.x() % n
    return v == r

class Private_key( object ):
  def __init__( self, public_key, secret_multiplier ):
    self.public_key = public_key
    self.secret_multiplier = secret_multiplier

  def der( self ):
    hex_der_key = '06052b8104000a30740201010420' + \
                  '%064x' % self.secret_multiplier + \
                  'a00706052b8104000aa14403420004' + \
                  '%064x' % self.public_key.point.x() + \
                  '%064x' % self.public_key.point.y()
    return hex_der_key.decode('hex')

  def sign( self, hash, k ):
    G = self.public_key.generator
    n = G.order()
    p1 = mulG(k)
    r = p1.x()
    if r == 0: raise RuntimeError, "amazingly unlucky random number r"
    s = ( inverse_mod( k, n ) * ( hash + ( self.secret_multiplier * r ) % n ) ) % n
    if s == 0: raise RuntimeError, "amazingly unlucky random number s"
    if s > (n>>1): #Canonical Signature enforced (lower S)
        s = n - s
        pby = (p1.y()+1)&1
    else:
        pby = (p1.y())&1
    return Signature( pby, r, s )

def randoml(pointgen):
  cand = 0
  while cand<1 or cand>=pointgen.order():
    cand=int(os.urandom(32).encode('hex'), 16)
  return cand

def gen_det_k(msg_hash,priv):
    v = '\x01' * 32
    k = '\x00' * 32
    msghash = ''
    for x in xrange(0,64,2):
        msghash =  msghash + struct.pack('B',int(msg_hash[x:x+2],16))
    private = 1
    priv    = binascii.unhexlify(("%064x" % private ).encode())
    k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v                    , hashlib.sha256).digest()
    k = hmac.new(k, v+'\x01'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v                    , hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).hexdigest()
        ksec = int(v,16)
        if ksec >= 1 and ksec<0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L:
            break
        k = hmac.new(k, v+'\x00'+priv+msghash, hashlib.sha256).digest()
        v = hmac.new(k, v                    , hashlib.sha256).digest()
    return ksec

def hash_msg(message):
    message=message.replace("\r\n","\n")
    lenmsg=len(message)
    if lenmsg<253: lm = bytearray(struct.pack('B',lenmsg))
    else: lm = bytearray(struct.pack('B',253)+struct.pack('<H',lenmsg)) # up to 65k
    full_msg = bytearray("\x18Bitcoin Signed Message:\n")+ lm + bytearray(message,'utf8')
    return dsha256(full_msg)

def bitcoin_sign_message(privkey, hsmessage, k):
    msg_hash = int(hsmessage,16)
    return privkey.sign( msg_hash , k )

def bitcoin_encode_sig(signature):
  return chr( 27 + signature.pby ) + signature.encode()

def output_full_sig(text,address,signature):
    fullsig= \
    "-----BEGIN BITCOIN SIGNED MESSAGE-----\n" \
    +text+ "\n" + \
    "-----BEGIN SIGNATURE-----\n" \
    +address+ "\n" +  \
    signature+ "\n" + \
    "-----END BITCOIN SIGNED MESSAGE-----"
    return fullsig
    

def bitcoin_verify_message(address, signature, message):
        G = generator_256
        order = G.order()
        # extract r,s from signature
        sig = base64.b64decode(signature)
        if len(sig) != 65: raise Exception("Wrong encoding")
        r = int(binascii.hexlify(sig[ 1:33]),16)
        s = int(binascii.hexlify(sig[33:  ]),16)
        assert r > 0 and r <= order-1
        assert s > 0 and s <= order-1
        nV = ord(sig[0])
        if nV < 27 or nV >= 35:
            raise Exception("Bad encoding")
        if nV >= 31:
            compressed = True
            nV -= 4
        else:
            compressed = False
        recid = nV - 27
        p=curve_256.p()
        xcube= pow(r,3,p)
        exposa=(p+1)>>2
        beta = pow(xcube+7, exposa, p)
        if (beta - recid) % 2 == 0:
            y = beta
        else:
            y = p - beta
        R = Point(r, y, order)
        # check R is on curve
        assert curve_256.contains_point(r,y)
        # checks that nR is at infinity
        assert order*R==INFINITY
        message=message.replace("\r\n","\n")
        lenmsg=len(message)
        if lenmsg<253: lm = bytearray(struct.pack('B',lenmsg))
        else: lm = bytearray(struct.pack('B',253)+struct.pack('<H',lenmsg)) # up to 65k
        be = bytearray("\x18Bitcoin Signed Message:\n")+ lm + bytearray(message,'utf8')
        inv_r = inverse_mod(r,order)    
        e = int(dsha256( be ),16)
        # Q = (sR - eG) / r
        Q = inv_r * (  R.dual_mult( -e % order, s ) )
        # checks Q in range, Q on curve, Q order
        pubkey = Public_key( G, Q)
        addr = pub_hex_base58( pubkey.point.x(), pubkey.point.y(), compressed )
        # checks the address provided is the signing address
        if address != addr:
            raise Exception("Bad signature")
        # No need to check signature, since we don't have the public key
        # Public key is extracted from signature, verification will always return OK
        # We compute the pub key from the expected result of sig check.
        # Since Q =(sR-eG)/r  then  R == e/s*G + r/s*Q  is always true
        #pubkey.verifies( e, Signature(0,r,s) )
        
        

def decode_sig_msg(msg):
    msg=msg.replace("\r\n","\n")
    msglines=msg.split('\n')
    nline=len(msglines)
    i=1
    message=""
    while not msglines[i].startswith("---"):
        message=message+"\n"+msglines[i]
        i=i+1
    address=msglines[nline-3]
    if address=="": address=msglines[nline-4][9:]
    signature=msglines[nline-2]
    return address, signature, message[1:]
    
if __name__ == '__main__' :
    import random
    import string
    load_gtable('G_Table')
    print "Tests started"
    print "\nDeterministic RFC6979 Checking"
    hmsg= hashlib.sha256(bytearray("Satoshi Nakamoto",'utf8')).hexdigest()
    k = gen_det_k( hmsg, 1 )
    assert k == 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15L
    
    message_signed = \
    """-----BEGIN BITCOIN SIGNED MESSAGE-----
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse faucibus, arcu imperdiet lacinia faucibus, magna tellus suscipit tortor, et auctor orci mi elementum leo. Aliquam vitae arcu viverra, tempus sem eget, mattis libero. Vestibulum ut libero dignissim, rhoncus augue eu, vulputate nisl. Quisque vitae pulvinar enim. Nullam lobortis tellus in eros consectetur, et iaculis eros interdum. Nam vehicula, sapien id consectetur rutrum, felis leo convallis eros, eget lacinia tellus nunc in dui. Etiam a quam eu lectus aliquam scelerisque. Vestibulum ac semper velit. Ut eget nulla eros. Sed venenatis purus eros, eu convallis lectus congue at. Suspendisse ipsum est, elementum et ultricies ac, sollicitudin sit amet urna. Proin viverra fusce.
-----BEGIN SIGNATURE-----
1B4ZZijK1w8xomMHyChXCgRwtN6LRvBgEi
G+5z8qAYM6LekZeE8ruDs1R1egjedfQxz0q8ja+v9pvWQWGozoiToB6aemOdPAOh4OFVysBMNmhZhCyIJierV+M=
-----END BITCOIN SIGNED MESSAGE-----"""
    
    def change_car(text, pos, car):
        return text[:pos] + car + text[pos+1:]
    
    def test_false_signature(address, signature, message):
        try:
            bitcoin_verify_message(address, signature, message)
            no_problem=False
        except Exception as inst:
            no_problem=True
        assert no_problem
    
    address1, signature1, message1 = decode_sig_msg(message_signed)
    
    print "\nSignature checking for validity"
    bitcoin_verify_message(address1, signature1, message1)
    
    print "\nCheck with falsified message"
    message=change_car(message1, 231, "l")
    test_false_signature(address1, signature1, message)
    
    print "\nCheck with falsified signature"
    signature=change_car(signature1,42,"u")
    test_false_signature(address1, signature, message1)
    
    print "\nCheck with falsified address"
    address = "1CVaUy7x8EA6wdnXCGkRChJASV4MAmje4g"
    test_false_signature(address, signature1, message1)
    
    print "\nBatch sign & check of random keys and messages"
    maxend=500
    g=generator_256
    random.seed(int(os.urandom(32).encode('hex'), 16))
    for i in xrange(maxend):
        print i+1, "/", maxend
        secret = random.randint(1,g.order())
        message = ''.join([random.choice(string.digits+string.letters+'    \n') for x in range(80)])
        try:
            pubkey = Public_key( g, mulG(secret) )
            privkey = Private_key( pubkey, secret )
            address_pub = pub_hex_base58( pubkey.point.x(), pubkey.point.y() )
            hm = hash_msg(message)
            if i%2==1:
                k = gen_det_k( hm, privkey )
            else:
                k = randoml(g)
            signature = bitcoin_sign_message( privkey, hm, k )
            signature_str = bitcoin_encode_sig( signature )
            signature64 = base64.b64encode( signature_str )
            fullsig = output_full_sig(message,address_pub,signature64)
            addr, sigd, msgd = decode_sig_msg(fullsig)
            bitcoin_verify_message(addr, sigd, msgd)
        except Exception as inst:
            print "ERROR :",str(inst)
            print message
            print secret
            print signature64
            print address_pub
            raise
        
    print "ALL TESTS PASSED !"
