#!/usr/bin/env python
# coding=utf8

# Ethereum Address Generation
# Copyright (C) 2015  Antoine FERRON
#
# Pure Python basic address generator
#
# Random source for key generation :
# CryptGenRandom in Windows
# /dev/urandom   in Unix-like
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# Uses python-sha3 from moshekaplan

from lib.ECDSA_BTC import *
import hashlib
import lib.python_sha3

def hashrand(num):
	#return sha256 of num times 256bits random data
	rng_data=''
	for idat in xrange(num):
		rng_data = rng_data + os.urandom(32)
	assert len(rng_data) == num*32
	return hashlib.sha256(rng_data).hexdigest()

def randomforkey():
	candint = 0
	r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
	while candint<1 or candint>=r:
		cand=hashrand(1024)
		candint=int(cand,16)
	return candint

print "\nGenerate new Ethereum address from random"
load_gtable('lib/G_Table')
privkeynum = randomforkey()
pubkey = Public_key( generator_256, mulG(privkeynum) )
pubkeyhex = (hexa(pubkey.point.x())+hexa(pubkey.point.y())).decode("hex")
address = lib.python_sha3.sha3_256(pubkeyhex).hexdigest()[-40:]
privkey = Private_key( pubkey, privkeynum )
print "\nAddress :  %s \n" % address
print "PrivKey :  %s" % hexa(privkeynum)
