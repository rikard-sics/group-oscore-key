#!/usr/bin/env python

from fields import GFp25519 as GFp, p25519 as p

import binascii

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

val1 = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'.decode('hex')
k_list1 = [ord(b) for b in val1]

val2 = 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'.decode('hex')
k_list2 = [ord(b) for b in val2]

print decodeLittleEndian(k_list1, 255);
print decodeLittleEndian(k_list2, 255);

# Test decodeScalar

val3 = '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3'.decode('hex')

val4 = '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'.decode('hex')

print decodeScalar(val3);
print decodeScalar(val4);

# Test decodeUCoord

val5 = 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'.decode('hex')

val6 = '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086'.decode('hex')

print decodeUCoord(val5);
print decodeUCoord(val6);

# Test encodeUCoord

val7 = 8883857351183929894090759386610649319417338800022198945255395922347792736741

val8 = 5834050823475987305959238492374969056969794868074987349740858586932482375934

print binascii.hexlify(encodeUCoord(val7));
print binascii.hexlify(encodeUCoord(val8));




