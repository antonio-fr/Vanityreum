#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Base58 of FSV
# Copyright (C) 2014  Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>


import hashlib
import binascii

b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def hexa(cha):
	hexas=hex(cha)[2:-1]
	while len(hexas)<64:
		hexas="0"+hexas
	return hexas

def hex_open_key_to_hex_hesh160(hex_open_key, compr=False, pary=0):
	h160 = hashlib.new('ripemd160')
	if compr:
		if pary==0: initchar='02'
		if pary==1: initchar='03'
	else: initchar='04'
	h160.update(hashlib.sha256((initchar+hex_open_key).decode('hex')).hexdigest().decode('hex'))
	return h160.hexdigest()
	
def hex_hesh160_to_hex_addr_v0(hex_hesh160):
	return '00'+hex_hesh160+hashlib.sha256(hashlib.sha256(('00'+hex_hesh160).decode('hex')).hexdigest().decode('hex')).hexdigest()[0:8]

def hex_priv_to_hex_addr(privh):
	return '80'+privh+hashlib.sha256(hashlib.sha256(('80'+privh).decode('hex')).hexdigest().decode('hex')).hexdigest()[0:8]

def hex_addr_v0_to_hex_hesh160(hex_addr_v0):
	return hex_addr_v0[2:-8]

def hex_to_base58(hex_data):
	base58 = ''
	int_data = int(hex_data, 16)
	while int_data >= len(b58chars):
		base58 = b58chars[int_data%len(b58chars)] + base58
		int_data = int_data/len(b58chars)
	base58 = b58chars[int_data%len(b58chars)] + base58
	for i in xrange(len(hex_data)/2):
		if hex_data[i*2:i*2+2] == '00':
			base58 = '1' + base58
		else:
			break
	return base58
	
def base58_to_hex(base58):
	hex_data = ''
	int_data = 0
	for i in xrange(-1, -len(base58)-1, -1):
		int_data += (b58chars.index(base58[i]))*58**(-i-1)
	hex_data = hex(int_data)[2:-1]
	for i in xrange(len(base58)):
		if base58[i] == '1':
			hex_data = '00' + hex_data
		else:
			break
	return hex_data

def extkey_base58_to_hex(base58):
	return hexa_extkey(base58_to_hex(base58))

def pub_base58(stri, compr=False, pary=0):
	return hex_to_base58(hex_hesh160_to_hex_addr_v0(hex_open_key_to_hex_hesh160(stri, compr, pary)))

def extpub_hex2base58(stri):
	initchar = stri[0:2]
	assert (initchar=='02' or initchar=='03')
	if initchar=='02': pary=0
	if initchar=='03': pary=1
	return hex_to_base58(hex_hesh160_to_hex_addr_v0(hex_open_key_to_hex_hesh160(stri[2:], True, pary)))

def priv_base58(stri):
	return hex_to_base58(hex_priv_to_hex_addr(stri))
	
def pub_hex_base58(x,y, compr=False):
	if compr: return pub_base58(hexa(x),True,y%2)
	else: return pub_base58(hexa(x)+hexa(y))

def priv_hex_base58(privl):
	return priv_base58(hexa(privl))

def pub_base58_hex(publ):
	assert publ[0]=="1"
	pubh=base58_to_hex(publ)
	pubhkey=pubh[2:-8]
	assert pubh[-8:]==hashlib.sha256(hashlib.sha256(('04'+pubhkey).decode('hex')).hexdigest().decode('hex')).hexdigest()[0:8]
	return pubhkey

def priv_base58_hex(privl):
	assert privl[0]=="5"
	privh=base58_to_hex(privl)
	privhkey=privh[2:-8]
	assert privh[-8:]==hashlib.sha256(hashlib.sha256(('80'+privhkey).decode('hex')).hexdigest().decode('hex')).hexdigest()[0:8]
	return privhkey

def extpub_base58_hex(publ):
	assert publ[:4]=="xpub"
	pubh=base58_to_hex(publ)
	pubhkey=pubh[7:-8]
	assert pubh[-8:]==hashlib.sha256(hashlib.sha256(('0488B21E'+pubhkey).decode('hex')).hexdigest().decode('hex')).hexdigest()[0:8]
	return pubhkey

