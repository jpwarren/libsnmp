# $Id$
# Copyright (c) 2003 Justin Warren <daedalus@eigenmagic.com>
# All Rights Reserved
#
# Stress/volume tests for encoding/decoding

import logging
import string

import random
import profile

import sys
sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155

# The number of objects to encode/decode in one go.
NUMBER_OF_OBJECTS = 10000

log = logging.getLogger('SVT Encoder Test')
log.setLevel(logging.DEBUG)
random.seed()

integers = []
object_ids = []

for i in range(NUMBER_OF_OBJECTS):
    # Generate a random integer
    integers.append( random.randrange( rfc1155.Integer.MINVAL, rfc1155.Integer.MAXVAL ) )

# set up some random ObjectIDs
for i in range(NUMBER_OF_OBJECTS):
    object_ids.append( [ 1, 3, 6, 1, random.randrange( 0, 50000 ), random.randrange( 0, 50000 ), random.randrange(0, 50000), random.randrange(0, 50000) ] )


def encodeRandomIntegers():
    for i in integers:
        octets = rfc1155.Integer(i).encode()

def encodeDecodeRandomIntegers():
    """ Test SVT Encode and Decode of Integer type
    """
    for i in integers:
        octets = rfc1155.Integer(i).encode()
        object = rfc1155.Asn1Object().decode(octets)

def encodeRandomObjectIDs():
    """ Test SVT Encode and Decode of ObjectID type
    """
    for i in object_ids:
        octets = rfc1155.ObjectID(i).encode()

def encodeDecodeRandomObjectIDs():
    """ Test SVT Encode and Decode of ObjectID type
    """
    for i in object_ids:
        octets = rfc1155.ObjectID(i).encode()
        object = rfc1155.Asn1Object().decode(octets)

if __name__ == '__main__':

#    print "Profiling encoding %d random integers..." % NUMBER_OF_OBJECTS
#    profile.run('encodeRandomIntegers()')

#    print "Profiling encoding/decoding of %d random integers..." % NUMBER_OF_OBJECTS
#    profile.run('encodeDecodeRandomIntegers()')

#    print "Profiling encoding of %d random ObjectIDs..." % NUMBER_OF_OBJECTS
#    profile.run('encodeRandomObjectIDs()')

    print "Profiling encoding/decoding of %d random ObjectIDs..." % NUMBER_OF_OBJECTS
    profile.run('encodeDecodeRandomObjectIDs()')

    logging.shutdown()
