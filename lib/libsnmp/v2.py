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
# SNMPv2 related functions

#import socket
#import select
import logging
#import Queue
#import time
#import os
#import asyncore

import traceback

from libsnmp import debug
from libsnmp import rfc1155
from libsnmp import rfc1157
from libsnmp import rfc1902
from libsnmp import rfc1905
#from libsnmp import asynrole

from libsnmp import v1
log = logging.getLogger('v2.SNMP')

class SNMP(v1.SNMP):

    def createGetRequestPDU(self, varbindlist):
        reqID = self.assignRequestID()
        pdu = rfc1905.Get( reqID, varBindList=varbindlist )
        return pdu

    def createGetNextRequestPDU(self, varbindlist):
        reqID = self.assignRequestID()
        pdu = rfc1905.GetNext( reqID, varBindList=varbindlist )
        return pdu

    def createGetRequestMessage(self, oid, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        objID = rfc1155.ObjectID(oid)
        val = rfc1155.Null()
        varbindlist = rfc1905.VarBindList( [ rfc1157.VarBind(objID, val) ] )
        pdu = self.createGetRequestPDU( varbindlist )
        return rfc1905.Message( community=community, data=pdu )

    def createGetNextRequestMessage(self, varbindlist, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        pdu = self.createGetNextRequest( varbindlist )
        return rfc1905.Message( community=community, data=pdu )

    def createTrapMessage(self, pdu, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        return rfc1905.Message( community=community, data=pdu )

    def createTrap(self, varbindlist, enterprise='.1.3.6.1.4', agentAddr=None, genericTrap=6, specificTrap=0):
        """ Creates a Trap PDU object from a list of strings and integers
            along with a varBindList to make it a bit easier to build a Trap.
        """
        ent = rfc1155.ObjectID(enterprise)
        if not agentAddr:
            agentAddr = self.sock.getsockname()[0]
        agent = rfc1155.NetworkAddress(agentAddr)
        gTrap = rfc1157.GenericTrap(genericTrap)
        sTrap = rfc1155.Integer(specificTrap)
        ts = rfc1155.TimeTicks( self.getSysUptime() )

        pdu = rfc1157.TrapPDU(ent, agent, gTrap, sTrap, ts, varbindlist)
        return pdu

    def snmpGet(self, oid, remote, callback, community='public'):
        """ snmpGet issues an SNMP Get Request to remote for
            the object ID oid 
            remote is a tuple of (host, port)
            oid is a dotted string eg: .1.2.6.1.0.1.1.3.0
        """
        msg = self.createGetRequestMessage( oid, community )
        # log.debug('sending message: %s' % msg)

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpGetNext(self, varbindlist, remote, callback, community='public'):
        """ snmpGetNext issues an SNMP Get Next Request to remote for
            the varbindlist that is passed in. It is assumed that you
            have either built a varbindlist yourself or just pass
            one in that was previously returned by an snmpGet or snmpGetNext
        """
        msg = self.createGetNextRequestMessage( varbindlist, community )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpSet(self, varbindlist, remote, callback, community='public'):
        """ An snmpSet requires a bit more up front smarts, in that
            you need to pass in a varbindlist of matching OIDs and
            values so that the value type matches that expected for the
            OID. This library does not care about any of that stuff.

        """
        reqID = self.assignRequestID()
        pdu = rfc1157.GetNextRequestPDU( reqID, varBindList=varbindlist )
        msg = rfc1905.Message( community=community, data=pdu )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[int(msg.data.requestID)] = callback
        return msg.data.requestID

    def snmpTrap(self, remote, trapPDU, community='public'):
        """ Queue up a trap for sending
        """
        msg = self.createTrapMessage(trapPDU, community)

        self.outbound.put( (msg, remote) )

    def createSetRequestMessage(self, varBindList, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """

    def receiveData(self, manager, cb_ctx, (data, src), (exc_type, exc_value, exc_traceback) ):
        """ This method should be called when data is received
            from a remote host.
        """
        # Exception handling
        if exc_type is not None:
            raise exc_type(exc_value)

        # perform the action on the message by calling the
        # callback from my list of callbacks, passing it the
        # message and a reference to myself

        try:
            # Decode the data into a message
            msg = rfc1905.Message().decode(data)

            # Decode it based on what version of message it is
            if msg.version == 0:
                log.debug('Detected SNMPv1 message')

            elif msg.version == 1:
                log.debug('Detected SNMPv2 message')

            else:
                log.error('Unknown message version %d detected' % msg.version)
                log.error('version is a %s' % msg.version() )
                raise ValueError('Unknown message version %d detected' % msg.version)

            # Figure out what kind of PDU the message contains
            if isinstance(msg.data, rfc1157.PDU):
#               if __debug__: log.debug('response to requestID: %d' % msg.data.requestID)
                self.callbacks[int(msg.data.requestID)](self, msg)

                # remove the callback from my list once it's done
                del self.callbacks[int(msg.data.requestID)]

            elif isinstance(msg.data, rfc1157.TrapPDU):
                if __debug__: log.debug('Detected an inbound Trap')
                self.trapCallback(self, msg)

            else:
                log.debug('Unknown message type')

        # log any errors in callback
        except Exception, e:
#            log.error('Exception in callback: %s: %s' % (self.callbacks[int(msg.data.requestID)].__name__, e) )
            log.error('Exception in receiveData: %s' % e )
            traceback.print_exc()
            #raise
