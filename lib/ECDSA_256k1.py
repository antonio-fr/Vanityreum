#! /usr/bin/env python
# coding=utf8

# ECDSA_256k1 of FastSignVerify
# Copyright (C) 2014  Antoine FERRON

# Some portions based on :
# "python-ecdsa" Copyright (C) 2010 Brian Warner (MIT Licence)
# "Simple Python elliptic curves and ECDSA" Copyright (C) 2005 Peter Pearson (public domain)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# secp256k1
_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
_r = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
_b = 0x0000000000000000000000000000000000000000000000000000000000000007L
#a = 0x00
_Gx= 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
_Gy= 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

class CurveFp( object ):
  def __init__( self, p, b ):
    self.__p = p
    self.__b = b

  def p( self ):
    return self.__p

  def b( self ):
    return self.__b

  def contains_point( self, x, y ):
    return ( y * y - ( x * x * x + self.__b ) ) % self.__p == 0

class Point( object ):
  def __init__( self, x, y, order = None ):
    self.__x = x
    self.__y = y
    self.__order = order

  def __eq__( self, other ):
    if self.__x == other.__x   \
     and self.__y == other.__y:
      return True
    else:
      return False

  def __add__( self, other ):
    if other == INFINITY: return self
    if self == INFINITY: return other
    p=curve_256.p()
    if self.__x == other.__x:
      if ( self.__y + other.__y ) % p == 0:
        return INFINITY
      else:
        return self.double()
    l = ( ( other.__y - self.__y ) * inverse_mod( other.__x - self.__x, p ) ) % p
    x3 = ( l * l - self.__x - other.__x ) % p
    return Point( x3, ( l * ( self.__x - x3 ) - self.__y ) % p )

  def __mul__( self, e ):
    if self.__order: e = e % self.__order
    if e == 0: return INFINITY
    if self == INFINITY: return INFINITY
    e3 = 3 * e
    negative_self = Point( self.__x, -self.__y, self.__order )
    i = 0x100000000000000000000000000000000000000000000000000000000000000000L
    while i > e3: i >>= 1
    result = self
    while i > 2:
      i >>= 1
      result = result.double()
      ei = e&i
      if (e3&i)^ei : 
        if ei==0   : result += self
        else         : result += negative_self
    return result

  def __rmul__( self, other ):
   return self * other

  def __str__( self ):
    if self == INFINITY: return "infinity"
    return "(%d,%d)" % ( self.__x, self.__y )

  def double( self ):
    p=curve_256.p()
    if self == INFINITY:
      return INFINITY
    xyd=((self.__x*self.__x)*inverse_mod(2*self.__y,p))%p
    x3=(9*xyd*xyd-2*self.__x)%p
    return Point( x3, (3*xyd*(self.__x-x3)-self.__y)%p )

  def dual_mult(self, k1, k2):
    # Compute k1.G+k2.self
    if self.__order: k2 = k2 % self.__order
    if k2 == 0: return INFINITY
    if self == INFINITY: return INFINITY
    if k1 == 0: return INFINITY
    assert k2 > 0
    assert k1 > 0
    e3, k3 = 3 * k2, 3 * k1
    negative_self = Point( self.__x, -self.__y, self.__order )
    neg_generator_256 = Point( _Gx, -_Gy, _r )
    i = 0x100000000000000000000000000000000000000000000000000000000000000000L
    ke3 = e3 | k3
    while i > ke3: i >>= 1
    if k3>e3:
      result = generator_256
      if (e3&i)==(k3&i): result += self
    else:
      result = self
      if (e3&i)==(k3&i): result += generator_256
    while i > 2:
      i >>= 1
      result = result.double()
      ei, ki = k2&i, k1&i
      if (e3&i)^ei : 
        if ei==0     : result +=  self
        else         : result += negative_self
      if (k3&i)^ki : 
        if ki==0     : result +=  generator_256
        else         : result += neg_generator_256
    return result
    
  def x( self ):
    return self.__x

  def y( self ):
    return self.__y

  def curve( self ):
    return self.__curve
  
  def order( self ):
    return self.__order
    
INFINITY = Point( None, None )

def inverse_mod( a, m ):
  if a < 0 or m <= a: a=a%m
  u, v = a,m
  xa,xb = 1,0
  while u != 1:
    q,r = divmod(v,u)
    x=xb-q*xa
    v,u,xb,xa = u,r,xa,x
  return xa%m

curve_256 = CurveFp( _p, _b )
generator_256 = Point( _Gx, _Gy, _r )
