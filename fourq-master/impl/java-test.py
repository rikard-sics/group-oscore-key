#!/usr/bin/env python

from fields import GFp25519 as GFp, p25519 as p

import binascii

# https://github.com/bifurcation/fourq

def decodeLittleEndian(b, bits):
    return sum([b[i] << 8*i for i in range((bits+7)/8)])

def decodeScalar(k):
    k_list = [ord(b) for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def decodeUCoord(u):
    bits = 255
    u_list = [ord(b) for b in u]
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1<<(bits%8))-1
    return decodeLittleEndian(u_list, bits)

def encodeUCoord(u):
    bits = 255
    u = u % p
    return ''.join([chr((u >> 8*i) & 0xff)
                    for i in range((bits+7)/8)])

# Test decodeLittleEndian

print "# Test decodeLittleEndian"

val1 = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'.decode('hex')
k_list1 = [ord(b) for b in val1]

val2 = 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'.decode('hex')
k_list2 = [ord(b) for b in val2]

print decodeLittleEndian(k_list1, 255);
print decodeLittleEndian(k_list2, 255);

# Test decodeScalar

print "# Test decodeScalar"

val3 = '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3'.decode('hex')

val4 = '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'.decode('hex')

print decodeScalar(val3);
print decodeScalar(val4);

# Test decodeUCoord

print "# Test decodeUCoord"

val5 = 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'.decode('hex')

val6 = '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086'.decode('hex')

print decodeUCoord(val5);
print decodeUCoord(val6);

# Test encodeUCoord

print "# Test encodeUCoord"

val7 = 8883857351183929894090759386610649319417338800022198945255395922347792736741

val8 = 5834050823475987305959238492374969056969794868074987349740858586932482375934

print binascii.hexlify(encodeUCoord(val7));
print binascii.hexlify(encodeUCoord(val8));

# Test cswap

print "# Test cswap"

val9_a = 8883857351183929894090759386610649319417338800022198945255395922347792736741
val9_b = 5834050823475987305959238492374969056969794868074987349740858586932482375934
swap = 1

print GFp.cswap(swap, val9_a, val9_b)

# Test X25519

def x25519(k, u):
    print "k", binascii.hexlify(k);
    print "u", binascii.hexlify(u);

    kn = decodeScalar(k)
    un = decodeUCoord(u)
    return encodeUCoord(x25519_inner(kn, un))

def x25519_inner(k, u):
    bits = 255
    a24 = 121665
    return transform(bits, a24, k, u)

def transform(bits, a24, k, u):

    bits = 255

    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0

    print "x1", x1
    print "x2", x2
    print "z2", z2
    print "x3", x3
    print "z3", z3

    for t in range(bits-1, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt

        if t >= 254:
          print "swap pre:", swap
          print "kt pre:", kt

        (x2, x3) = GFp.cswap(swap, x2, x3)
        (z2, z3) = GFp.cswap(swap, z2, z3)
        swap = kt

        if t >= 254:
          print "A CALC"
          print "x2", x2
          print "z2", z2
          print "kt", kt
          print "swap", swap

        A = GFp.add(x2, z2)
        AA = GFp.sqr(A)
        B = GFp.sub(x2, z2)
        BB = GFp.sqr(B)
        E = GFp.sub(AA, BB)

        C = GFp.add(x3, z3)
        D = GFp.sub(x3, z3)
        DA = GFp.mul(D, A)
        CB = GFp.mul(C, B)

        FF = GFp.sqr(GFp.add(DA, CB))
        GG = GFp.sqr(GFp.sub(DA, CB))

        x3 = FF
        z3 = GFp.mul(x1, GG)
        x2 = GFp.mul(AA, BB)
        z2 = GFp.mul(E, GFp.add(AA, GFp.mul(a24, E)))

        #print "t", t
        if t >= 254:
          print ".t", t
          print ".kt", kt
          print ".A", A
          print ".AA", AA
          print ".B", B
          print ".BB", BB
          print ".E", E

          print ".C", C
          print ".D", D
          print ".DA", DA
          print ".CB", CB

          print ".x1", x1
          print ".x2", x2
          print ".z2", z2
          print ".x3", x3
          print ".z3", z3

          print ".swap", swap

    (x2, x3) = GFp.cswap(swap, x2, x3)
    (z2, z3) = GFp.cswap(swap, z2, z3)
    return GFp.mul(x2, GFp.inv(z2))

k0 = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'.decode('hex')
u0 = 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'.decode('hex')
r0 = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'.decode('hex')

rp = x25519(k0, u0)
print binascii.hexlify(rp);

# Non working test case

inU = '0900000000000000000000000000000000000000000000000000000000000000'.decode('hex')
inK = '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'.decode('hex')

rr = x25519(inK, inU);

print rr
