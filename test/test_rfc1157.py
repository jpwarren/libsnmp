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
# Unit tests for rfc1157

import unittest
import logging

import sys
sys.path.append('../lib')

from libsnmp import util
from libsnmp import debug
from libsnmp import rfc1155
from libsnmp import rfc1157

# Set up some pre-encoded integers and the actual integer
# values that they should decode to

class rfc1157Test(unittest.TestCase):

    def setUp(self):
        self.log = logging.getLogger('1157Test')
        self.log.setLevel(logging.DEBUG)

    def tearDown(self):
        logging.shutdown()

    def test_varBindEncode(self):
        """ Test encode/decode of a VarBind
        """
        myobj = rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) )
#        self.log.debug('object: %s' % myobj)
        octets = myobj.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1157.VarBind().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )


    def test_varBindListEncode(self):
        """ Test encode/decode of a VarBindList
        """
        myList = []
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.4.5.4.55.4465.7'), rfc1155.Null() ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.2.5.8.6858.7'), 
                rfc1155.Sequence([ rfc1155.OctetString('blah'), rfc1155.NetworkAddress('10.232.8.6') ]) ) )
#        self.log.debug('mylist: %s' % myList)
        myVarBindList = rfc1157.VarBindList( myList )
#        self.log.debug('myvarlist: %s' % myVarBindList)
        octets = myVarBindList.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1155.Asn1Object().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )

    def test_getRequestEncode(self):
        myList = []
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.4.5.4.55.4465.7'), rfc1155.Null() ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.2.5.8.6858.7'), 
                rfc1155.Sequence([ rfc1155.OctetString('blah'), rfc1155.NetworkAddress('10.232.8.6') ]) ) )
        myVarBindList = rfc1157.VarBindList( myList )

#        self.log.debug('myvarlist: %s' % myVarBindList)
        obj = rfc1157.GetRequestPDU(5, varBindList=myVarBindList)
#        self.log.debug('obj: %s: %s' % (obj.__class__, obj) )
        octets = obj.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1157.RequestPDU().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )

    def test_getNextRequestEncode(self):
        myList = []
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.4.5.4.55.4465.7'), rfc1155.Null() ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.2.5.8.6858.7'), 
                rfc1155.Sequence([ rfc1155.OctetString('blah'), rfc1155.NetworkAddress('10.232.8.6') ]) ) )
        myVarBindList = rfc1157.VarBindList( myList )
#        self.log.debug('myvarlist: %s' % myVarBindList)
        obj = rfc1157.GetNextRequestPDU(5, varBindList=myVarBindList)
#        self.log.debug('obj: %s: %s' % (obj.__class__, obj) )
        octets = obj.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1157.RequestPDU().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )

    def test_getResponseEncode(self):
        myList = []
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.4.5.4.55.4465.7'), rfc1155.Null() ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.2.5.8.6858.7'), 
                rfc1155.Sequence([ rfc1155.OctetString('blah'), rfc1155.NetworkAddress('10.232.8.6') ]) ) )
        myVarBindList = rfc1157.VarBindList( myList )
#        self.log.debug('myvarlist: %s' % myVarBindList)
        obj = rfc1157.GetResponsePDU(5, varBindList=myVarBindList)
#        self.log.debug('obj: %s: %s' % (obj.__class__, obj) )
        octets = obj.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1157.RequestPDU().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )

    def test_setRequestEncode(self):
        myList = []
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.0.3.4.5.7'), rfc1155.Integer(47) ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.4.5.4.55.4465.7'), rfc1155.Null() ) )
        myList.append( rfc1157.VarBind( rfc1155.ObjectID('.1.2.5.8.6858.7'), 
                rfc1155.Sequence([ rfc1155.OctetString('blah'), rfc1155.NetworkAddress('10.232.8.6') ]) ) )
        myVarBindList = rfc1157.VarBindList( myList )
#        self.log.debug('myvarlist: %s' % myVarBindList)
        obj = rfc1157.SetRequestPDU(5, varBindList=myVarBindList)
#        self.log.debug('obj: %s: %s' % (obj.__class__, obj) )
        octets = obj.encode()
#        self.log.debug('octets: %s' % util.octetsToHex(octets) )
        objectList = rfc1157.RequestPDU().decode(octets)
#        for item in objectList:
#            self.log.debug('item: %s: %s' % (item.__class__, item) )

if __name__ == '__main__':
    unittest.main()

