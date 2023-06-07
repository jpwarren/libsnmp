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
# Unit tests for the encoder/decoder

import unittest
import logging
import string

import sys
sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155

class EncoderTest(unittest.TestCase):
    
    def setUp(self):
        self.log = logging.getLogger('EncoderTest')
        self.log.setLevel(logging.DEBUG)
        return
    
    def tearDown(self):
        logging.shutdown()
        return
    
    def test_objectid_equality(self):
        
        """test equality of objects sourced from different initialisation values"""
        
        input_a = [1,3,6,1,2,1,2,3,234,23,4,23,423,234,23423423,4234] # list
        input_b = tuple(input_a)        # tuple
        input_c = '.'.join( [ str(x) for x in input_a] ) # string no leading dot
        input_d = '.' + input_c         # string leading dot
        
        a = rfc1155.ObjectID(input_a)
        b = rfc1155.ObjectID(input_b)
        c = rfc1155.ObjectID(input_c)
        d = rfc1155.ObjectID(input_d)
        e = rfc1155.ObjectID('.1.3')
        f = rfc1155.ObjectID().decode(a.encode())[0]
        g = rfc1155.Asn1Object().decode(a.encode())[0]        
        
        self.assertEqual(a, a)
        self.assertEqual(a, b)
        self.assertEqual(a, c)
        self.assertEqual(a, d)
        self.assertNotEqual(a, e)
        self.assertEqual(a, f)
        self.assertEqual(a, g)        
        
        self.assertEqual(b, a)
        self.assertEqual(b, b)
        self.assertEqual(b, c)
        self.assertEqual(b, d)
        self.assertNotEqual(b, e)        
        self.assertEqual(b, f)
        self.assertEqual(b, g)        
        
        pass

    def test_integer(self):
        
        a = rfc1155.Integer(0)
        b = rfc1155.Integer(0x7FFFFFFF)
        c = rfc1155.Integer(-1)
        d = rfc1155.Integer(-0x7FFFFFF)
        
        return

    def test_ip_address(self):
        
        addresses = (('0.0.0.0',          '@\x04\x00\x00\x00\x00'),
                     ('255.255.255.255',  '@\x04\xff\xff\xff\xff'),
                     ('1.2.3.4',          '@\x04\x01\x02\x03\x04'),
                     ('10.0.0.1',         '@\x04\n\x00\x00\x01'),
                     ('254.154.1.0',      '@\x04\xfe\x9a\x01\x00'),
                     ('0.0.0.1',          '@\x04\x00\x00\x00\x01'),
                     ('255.0.0.0',        '@\x04\xff\x00\x00\x00'))
        
        for input, output in addresses:
            a = rfc1155.IPAddress(input)
            raw = a.encode()
            b = rfc1155.Asn1Object().decode(raw)[0]
            self.assertEqual(a,b)
            pass
        return
    
    
    def test_objectid_length(self):
        
        """test length"""
        
        input_a = [1,3,6,1,2,1,2,3,234,23,4,23,423,234,23423423,4234] # list
        input_b = tuple(input_a)        # tuple
        input_c = '.'.join( [ str(x) for x in input_a] ) # string no leading dot
        input_d = '.' + input_c         # string leading dot
        
        a = rfc1155.ObjectID(input_a)
        b = rfc1155.ObjectID(input_b)
        c = rfc1155.ObjectID(input_c)
        d = rfc1155.ObjectID(input_d)
        e = rfc1155.ObjectID('.1.3')
        
        self.assertEqual(len(a), len(input_a))
        self.assertEqual(len(b), len(input_a))
        self.assertEqual(len(c), len(input_a))
        self.assertEqual(len(d), len(input_a))
        self.assertNotEqual(len(b), len(e))
        
        return
    
    pass

if __name__ == '__main__':
    unittest.main()

