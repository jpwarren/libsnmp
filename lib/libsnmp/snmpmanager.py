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

## An snmpmanager understands SNMPv1 and SNMPv2c messages
## and so it can encode and decode both.

import socket
import select
import logging
import Queue
import time
import os
import asyncore

from libsnmp import debug
from libsnmp import asynrole

from libsnmp import rfc1157
from libsnmp import rfc1905

log = logging.getLogger('snmp-manager')

class snmpManager(asynrole.manager):

    nextRequestID = 0L      # global counter of requestIDs

    def __init__(self, queueEmpty=None, trapCallback=None, interface=('0.0.0.0', 0), timeout=0.25):
        """ Create a new snmpManager bound to interface
            queueEmpty is a callback of what to do if I run out
            of stuff to do. Default is to wait for more stuff.
        """
        self.queueEmpty = queueEmpty
        self.outbound = Queue.Queue()
        self.callbacks = {}

        # What to do if we get a trap
        self.trapCallback = trapCallback

        # initialise as an asynrole manager
        asynrole.manager.__init__(self, (self.receiveData, None), interface=interface, timeout=timeout )

        try:
            # figure out the current system uptime

            pass

        except:
            raise

    def assignRequestID(self):
        """ Assign a unique requestID 
        """
        reqID = self.nextRequestID
        self.nextRequestID += 1
        return reqID

    def createGetRequestPDU(self, varbindlist, version=2):
        reqID = self.assignRequestID()

        if version == 1:
            pdu = rfc1157.Get( reqID, varBindList=varbindlist )

        elif version == 2:
            pdu = rfc1905.Get( reqID, varBindList=varbindlist )            
            
        return pdu

    def createGetNextRequestPDU(self, varbindlist, version=2):
        reqID = self.assignRequestID()
        
        if version == 1:
            pdu = rfc1157.GetNext( reqID, varBindList=varbindlist )

        elif version == 2:
            pdu = rfc1905.GetNext( reqID, varBindList=varbindlist )
            
        return pdu

    def createGetRequestMessage(self, oid, community='public', version=2):
        """ Creates a message object from a pdu and a
            community string.
        """
        if version == 1:
            objID = rfc1157.ObjectID(oid)
            val = rfc1157.Null()
            varbindlist = rfc1157.VarBindList( [ rfc1157.VarBind(objID, val) ] )
            pdu = self.createGetRequestPDU( varbindlist, 1 )
            message = rfc1157.Message( community=community, data=pdu )

        elif version == 2:
            objID = rfc1905.ObjectID(oid)
            val = rfc1905.Null()
            varbindlist = rfc1905.VarBindList( [ rfc1905.VarBind(objID, val) ] )
            pdu = self.createGetRequestPDU( varbindlist, 2 )
            message = rfc1905.Message( community=community, data=pdu )

        else:
            raise ValueError('Unknown version %d' % version)

        return message

    def createGetNextRequestMessage(self, varbindlist, community='public', version=2):
        """ Creates a message object from a pdu and a
            community string.
        """
        pdu = self.createGetNextRequestPDU( varbindlist, version )

        if version == 1:
            return rfc1157.Message( community=community, data=pdu )

        if version == 2:
            return rfc1905.Message( community=community, data=pdu )

    def createTrapMessage(self, pdu, community='public'):
        """ Creates a message object from a pdu and a
            community string.
        """
        return Message( community=community, data=pdu )

    def createTrapPDU(self, varbindlist, enterprise='.1.3.6.1.4', agentAddr=None, genericTrap=6, specificTrap=0):
        """ Creates a Trap PDU object from a list of strings and integers
            along with a varBindList to make it a bit easier to build a Trap.
        """
        ent = ObjectID(enterprise)
        if not agentAddr:
            agentAddr = self.sock.getsockname()[0]
        agent = NetworkAddress(agentAddr)
        gTrap = GenericTrap(genericTrap)
        sTrap = Integer(specificTrap)
        ts = TimeTicks( self.getSysUptime() )

        pdu = TrapPDU(ent, agent, gTrap, sTrap, ts, varbindlist)
#        log.debug('v1.trap is %s' % pdu)
        return pdu

    def snmpGet(self, oid, remote, callback, community='public', version=2):
        """ snmpGet issues an SNMP Get Request to remote for
            the object ID oid 
            remote is a tuple of (host, port)
            oid is a dotted string eg: .1.2.6.1.0.1.1.3.0
        """
        msg = self.createGetRequestMessage( oid, community, version )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[msg.data.requestID] = callback

        return msg.data.requestID

    def snmpGetNext(self, varbindlist, remote, callback, community='public', version=2):
        """ snmpGetNext issues an SNMP Get Next Request to remote for
            the varbindlist that is passed in. It is assumed that you
            have either built a varbindlist yourself or just pass
            one in that was previously returned by an snmpGet or snmpGetNext
        """
        msg = self.createGetNextRequestMessage( varbindlist, community, version )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[msg.data.requestID] = callback
        return msg.data.requestID

    def snmpSet(self, varbindlist, remote, callback, community='public', version=2):
        """ An snmpSet requires a bit more up front smarts, in that
            you need to pass in a varbindlist of matching OIDs and
            values so that the value type matches that expected for the
            OID. This library does not care about any of that stuff.

        """
        reqID = self.assignRequestID()
        if version == 1:
            pdu = v1.Set( reqID, varBindList=varbindlist )
            msg = v1.Message( community=community, data=pdu )

        if version == 2:
            pdu = v2.Set( reqID, varBindList=varbindlist )
            msg = v2.Message( community=community, data=pdu )

        # add this message to the outbound queue as a tuple
        self.outbound.put( (msg, remote) )
        # Add the callback to my dictionary with the requestID
        # as the key for later retrieval
        self.callbacks[msg.data.requestID] = callback
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
                self.handleV1Message(msg)

            elif msg.version == 1:
                log.debug('Detected SNMPv2 message')
                self.handleV2Message(msg)

            else:
                log.error('Unknown message version %d detected' % msg.version)
                log.error('version is a %s' % msg.version() )
                raise ValueError('Unknown message version %d detected' % msg.version)
        # log any errors in callback
        except Exception, e:
#            log.error('Exception in callback: %s: %s' % (self.callbacks[int(msg.data.requestID)].__name__, e) )
            log.error('Exception in receiveData: %s' % e )
            raise

    def handleV1Message(self, msg):
        """ Handle reception of an SNMP version 1 message 
        """
        if isinstance(msg.data, rfc1157.PDU):
            self.callbacks[msg.data.requestID](self, msg)

            ## remove the callback from my list once it's done
            del self.callbacks[msg.data.requestID]

        elif isinstance(msg.data, rfc1157.TrapPDU):
            self.trapCallback(self, msg)

        else:
            log.info('Unknown SNMPv1 Message type received')
        pass

    def handleV2Message(self, msg):
        """ Handle reception of an SNMP version 2c message
        """
        if isinstance(msg.data, rfc1905.PDU):
            self.callbacks[msg.data.requestID](self, msg)

            ## remove the callback from my list once it's done
            del self.callbacks[msg.data.requestID]

        elif isinstance(msg.data, rfc1905.TrapPDU):
            self.trapCallback(self, msg)

        else:
            log.info('Unknown SNMPv2 Message type received')
        pass

    def enterpriseOID(self, partialOID):
        """ A convenience method to automagically prepend the
            'enterprise' prefix to the partial OID
        """
        return '.1.3.6.1.2.1.' + partialOID

    def run(self):
        """ Listen for incoming request thingies
            and send pending requests
        """
        while 1:
            try:
                # send any pending outbound messages
                request = self.outbound.get(0)
                self.send( request[0].encode(), request[1] )

                # check for inbound messages
                self.poll()

            except Queue.Empty:
                if self.queueEmpty:
                    self.queueEmpty(self)
                pass

            except:
                raise

    def getSysUptime(self):
        """ This is a pain because of system dependence
            Each OS has a different way of doing this and I
            cannot find a Python builtin that will do it.
        """
        try:
            ##
            ## The linux way
            ##
            uptime = open('/proc/uptime').read().split()
            upsecs = int(float(uptime[0]) * 100)

            return upsecs

        except:
            return 0
