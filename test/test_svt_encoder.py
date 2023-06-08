#!/usr/bin/env python
# $Id$
# $Revision$
#
#    libsnmp - a Python SNMP library
#    Copyright (C) 2003 Unicity Pty Ltd <libsnmp@unicity.com.au>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Stress/volume tests for encoding/decoding

import logging
import string
import time

import random
import profile

import sys
sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155

# The number of objects to encode/decode in one go.
NUMBER_OF_OBJECTS = 50000

log = logging.getLogger('SVT Encoder Test')
log.setLevel(logging.DEBUG)
random.seed()

integers = []
object_ids = []

start = time.time()

for i in range(NUMBER_OF_OBJECTS):
    # Generate a random integer
    integers.append( random.randrange( rfc1155.Integer.MINVAL, rfc1155.Integer.MAXVAL ) )
    pass

# set up some random ObjectIDs
for i in range(NUMBER_OF_OBJECTS):
    object_ids.append( [ 1, 3, 6, 1, random.randrange( 0, 50000 ), random.randrange( 0, 50000 ), random.randrange(0, 50000), random.randrange(0, 50000) ] )
    pass

def encodeRandomIntegers():
    for i in integers:
        octets = rfc1155.Integer(i).encode()
        pass
    pass

def encodeDecodeRandomIntegers():
    """ Test SVT Encode and Decode of Integer type
    """
    for i in integers:
        octets = rfc1155.Integer(i).encode()
        object = rfc1155.Asn1Object().decode(octets)
        pass
    pass

def encodeRandomObjectIDs():
    """ Test SVT Encode and Decode of ObjectID type
    """
    for i in object_ids:
        octets = rfc1155.ObjectID(i).encode()
        pass
    pass

def encodeDecodeRandomObjectIDs():
    """ Test SVT Encode and Decode of ObjectID type
    """
    for i in object_ids:
        octets = rfc1155.ObjectID(i).encode()
        object = rfc1155.Asn1Object().decode(octets)
        pass
    pass

def go():
    encodeDecodeRandomObjectIDs()
    encodeDecodeRandomIntegers()
    pass

if __name__ == '__main__':
    
    #    print "Profiling encoding %d random integers..." % NUMBER_OF_OBJECTS
    #    profile.run('encodeRandomIntegers()')
    
    #    print "Profiling encoding/decoding of %d random integers..." % NUMBER_OF_OBJECTS
    #    profile.run('encodeDecodeRandomIntegers()')
    
    #    print "Profiling encoding of %d random ObjectIDs..." % NUMBER_OF_OBJECTS
    #    profile.run('encodeRandomObjectIDs()')
    
    print("Profiling encoding/decoding of %d random ObjectIDs..." % NUMBER_OF_OBJECTS)
    profile.run('go()')
    
    #encodeDecodeRandomObjectIDs()  
    
    end = time.time()
    diff = end - start
    print('time to run %4.2f seconds' % diff)
    logging.shutdown()
